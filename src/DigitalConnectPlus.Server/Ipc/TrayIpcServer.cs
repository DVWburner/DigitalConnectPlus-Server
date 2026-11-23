using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Data;
using DigitalConnectPlus.Server.Models;
using DigitalConnectPlus.Server.Services;
using DigitalConnectPlus.Server.Tls;

namespace DigitalConnectPlus.Server.Ipc;

public sealed class IpcCommandMessage
{
    public string Action { get; set; } = "";
    public ServerSettings? Settings { get; set; }
    public string? TokenLabel { get; set; }
    public int? MaxCars { get; set; }
    public int? TokenId { get; set; }
}

public sealed class IpcResponseMessage
{
    public bool Ok { get; set; }
    public string? Message { get; set; }
    public bool RequiresServiceRestart { get; set; }
    public ServerLiveStatusDto? Status { get; set; }
    public ServerSettings? Settings { get; set; }
    public List<ApiTokenSummaryDto>? ApiTokens { get; set; }
    public string? CreatedPlainToken { get; set; }
}

/// <summary>
/// Local Named Pipe IPC server allowing the Windows System Tray UI to monitor live metrics,
/// update settings, trigger Let's Encrypt issuance/renewal, and manage API tokens securely.
/// Restricted via Windows ACLs to Administrators, SYSTEM, and Authenticated Interactive Users on local machine.
/// </summary>
public sealed class TrayIpcServer : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private readonly SettingsManager _settings;
    private readonly RelayDatabase _db;
    private readonly CertificateProvider _certProvider;
    private readonly AcmeLetsEncryptService _acme;
    private readonly CarPollNotifier _notifier;
    private readonly MetricsTracker _metrics;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<TrayIpcServer> _logger;

    public string ActiveListenerDescription { get; set; } = "Starting...";

    public TrayIpcServer(
        SettingsManager settings,
        RelayDatabase db,
        CertificateProvider certProvider,
        AcmeLetsEncryptService acme,
        CarPollNotifier notifier,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        ILogger<TrayIpcServer> logger)
    {
        _settings = settings;
        _db = db;
        _certProvider = certProvider;
        _acme = acme;
        _notifier = notifier;
        _metrics = metrics;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = CreateSecuredPipeServer();
                await pipe.WaitForConnectionAsync(stoppingToken);
                _ = HandleClientConnectionAsync(pipe, stoppingToken);
                pipe = null; // Ownership transferred
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                pipe?.Dispose();
                _logger.LogWarning(ex, "Named pipe listener error; retrying in 2s.");
                try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken); } catch { break; }
            }
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateSecuredPipeServer()
    {
        var pipeSecurity = new PipeSecurity();
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        // Allow interactive desktop session user to connect for read-only status (writes still require Admin check!)
        pipeSecurity.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            ServerConstants.AdminPipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 65_536,
            outBufferSize: 65_536,
            pipeSecurity);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool CheckCallerIsAdmin(NamedPipeServerStream pipe)
    {
        bool isAdmin = false;
        try
        {
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator) || identity.IsSystem;
            });
        }
        catch
        {
            isAdmin = false;
        }
        return isAdmin;
    }

    private async Task HandleClientConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 16_384, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 16_384, leaveOpen: true) { AutoFlush = true };

                string? line = await reader.ReadLineAsync(ct);
                if (string.IsNullOrWhiteSpace(line) || line.Length > 131_072)
                    return;

                // Windows requires at least one read from the named pipe before ImpersonateNamedPipeClient (RunAsClient) succeeds.
                bool callerIsAdmin = OperatingSystem.IsWindows() && CheckCallerIsAdmin(pipe);

                IpcCommandMessage? cmd = JsonSerializer.Deserialize<IpcCommandMessage>(line, JsonOpts);
                if (cmd == null)
                    return;

                IpcResponseMessage response = await DispatchAsync(cmd, callerIsAdmin, ct);
                string outJson = JsonSerializer.Serialize(response, JsonOpts);
                await writer.WriteLineAsync(outJson);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "IPC client handling error.");
            }
        }
    }

    private async Task<IpcResponseMessage> DispatchAsync(IpcCommandMessage cmd, bool callerIsAdmin, CancellationToken ct)
    {
        string action = (cmd.Action ?? "").Trim().ToLowerInvariant();
        long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();

        if (action == "get_status")
        {
            var (cars, queued) = await _db.GetDashboardCountsAsync(nowMs, ct);
            ServerSettings s = _settings.Current;
            CertificateSnapshot? snap = _certProvider.CurrentSnapshot;

            return new IpcResponseMessage
            {
                Ok = true,
                Status = new ServerLiveStatusDto
                {
                    Version = ServerConstants.Version,
                    UptimeSeconds = _metrics.UptimeSeconds,
                    ListenerSummary = ActiveListenerDescription,
                    PublicUrl = s.PublicUrl,
                    AuthMode = s.AuthMode,
                    TlsMode = s.TlsMode,
                    CertificateStatus = _certProvider.StatusMessage,
                    CertificateSubject = snap?.Subject,
                    CertificateThumbprint = snap?.Thumbprint,
                    CertificateExpiresUtc = snap?.NotAfterUtc.ToString("yyyy-MM-dd HH:mm 'UTC'"),
                    RequestsLastMinute = _metrics.GetRequestsInLastMinute(),
                    TotalRequestsServed = _metrics.TotalRequests,
                    ActiveLongPolls = _notifier.ActivePollCount,
                    RegisteredCarCount = cars,
                    QueuedCommandCount = queued,
                    RecentEvents = _metrics.GetRecentEvents()
                }
            };
        }

        if (!callerIsAdmin)
        {
            return new IpcResponseMessage
            {
                Ok = false,
                Message = "Administrator privileges are required to view secrets or modify server configuration. Run Digital Connect+ Tray as Administrator."
            };
        }

        switch (action)
        {
            case "get_settings":
                return new IpcResponseMessage
                {
                    Ok = true,
                    Settings = _settings.Current.Clone()
                };

            case "save_settings":
                if (cmd.Settings == null)
                    return new IpcResponseMessage { Ok = false, Message = "Missing settings payload." };

                ServerSettings prev = _settings.Current;
                bool bindingChanged =
                    !string.Equals(prev.ListenerEngine, cmd.Settings.ListenerEngine, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(prev.ListenInterface, cmd.Settings.ListenInterface, StringComparison.OrdinalIgnoreCase) ||
                    prev.Port != cmd.Settings.Port ||
                    prev.EnableHttpAcmeListener != cmd.Settings.EnableHttpAcmeListener ||
                    prev.HttpAcmePort != cmd.Settings.HttpAcmePort ||
                    !string.Equals(prev.CustomBindUrl, cmd.Settings.CustomBindUrl, StringComparison.OrdinalIgnoreCase) ||
                    (string.Equals(prev.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase) !=
                     string.Equals(cmd.Settings.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase));

                _settings.Save(cmd.Settings);
                if (string.Equals(cmd.Settings.TlsMode, "SelfSignedLocal", StringComparison.OrdinalIgnoreCase) &&
                    (!string.Equals(prev.PublicUrl, cmd.Settings.PublicUrl, StringComparison.OrdinalIgnoreCase) ||
                     !string.Equals(prev.ListenInterface, cmd.Settings.ListenInterface, StringComparison.OrdinalIgnoreCase)))
                {
                    try { File.Delete(_certProvider.GetSelfSignedPfxPath()); } catch { }
                }
                _certProvider.ReloadCertificate();
                _metrics.LogEvent("CFG", "Configuration saved via Tray Control Panel.");

                return new IpcResponseMessage
                {
                    Ok = true,
                    RequiresServiceRestart = bindingChanged,
                    Message = bindingChanged
                        ? "Settings saved. Listener binding changed — restarting service to bind new endpoint."
                        : "Settings saved and applied live."
                };

            case "renew_letsencrypt":
                var (ok, msg) = await _acme.IssueOrRenewNowAsync(force: true, ct);
                return new IpcResponseMessage { Ok = ok, Message = msg };

            case "list_tokens":
                return new IpcResponseMessage
                {
                    Ok = true,
                    ApiTokens = await _db.ListApiTokensAsync(ct)
                };

            case "create_token":
                int maxCars = Math.Max(1, cmd.MaxCars ?? _settings.Current.MaxCarsPerAccount);
                var (plain, _) = await _db.CreateApiTokenAsync(cmd.TokenLabel ?? "User Token", maxCars, nowMs, ct: ct);
                _metrics.LogEvent("AUTH", $"Issued new API token ({cmd.TokenLabel ?? "User Token"}).");
                return new IpcResponseMessage
                {
                    Ok = true,
                    CreatedPlainToken = plain,
                    Message = "API Token created. Copy it now — it will not be shown in plaintext again.",
                    ApiTokens = await _db.ListApiTokensAsync(ct)
                };

            case "revoke_token":
                if (!cmd.TokenId.HasValue)
                    return new IpcResponseMessage { Ok = false, Message = "Missing tokenId." };
                bool revoked = await _db.RevokeApiTokenAsync(cmd.TokenId.Value, ct);
                _metrics.LogEvent("AUTH", $"Revoked API token #{cmd.TokenId.Value}.");
                return new IpcResponseMessage
                {
                    Ok = revoked,
                    Message = revoked ? "Token revoked." : "Token not found.",
                    ApiTokens = await _db.ListApiTokensAsync(ct)
                };

            default:
                return new IpcResponseMessage { Ok = false, Message = $"Unknown IPC action '{action}'." };
        }
    }
}
