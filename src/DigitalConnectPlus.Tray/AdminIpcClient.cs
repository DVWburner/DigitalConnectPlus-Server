using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;

namespace DigitalConnectPlus.Tray;

public sealed class TrayServerSettings
{
    public string PublicUrl { get; set; } = "";
    public string ListenerEngine { get; set; } = "Kestrel";
    public string ListenInterface { get; set; } = "0.0.0.0";
    public int Port { get; set; } = 8443;
    public bool EnableHttpAcmeListener { get; set; } = false;
    public int HttpAcmePort { get; set; } = 80;
    public string CustomBindUrl { get; set; } = "";
    public string TlsMode { get; set; } = "WindowsCertStore";
    public string WindowsCertStoreLocation { get; set; } = "LocalMachine";
    public string WindowsCertStoreName { get; set; } = "My";
    public string WindowsCertThumbprint { get; set; } = "";
    public bool AutoMatchCertByPublicUrlHost { get; set; } = true;
    public string PfxFilePath { get; set; } = "";
    public string PfxPasswordProtectedBase64 { get; set; } = "";
    public string PfxPasswordPlain { get; set; } = "";
    public string LetsEncryptEmail { get; set; } = "";
    public bool LetsEncryptUseStaging { get; set; } = false;
    public bool LetsEncryptAutoRenew { get; set; } = true;
    public int LetsEncryptRenewDaysBeforeExpiry { get; set; } = 30;
    public bool LetsEncryptImportToWindowsStore { get; set; } = false;
    public string AuthMode { get; set; } = "device_pop_only";
    public string ServerSharedToken { get; set; } = "";
    public bool AllowPublicAccountRegistration { get; set; } = true;
    public int MaxCarsPerAccount { get; set; } = 5;
    public int TokenLifetimeDays { get; set; } = 30;
    public string JwtIssuer { get; set; } = "digital-connect-plus";
    public string JwtAudience { get; set; } = "gen5w-digital-control";
    public int MaxQueuedCommandsPerCar { get; set; } = 20;
    public int RateLimitPerIpPerMinute { get; set; } = 100;
    public int RateLimitPerCarPerMinute { get; set; } = 40;
    public int MaxRequestBodyBytes { get; set; } = 262_144;
    public bool TrustForwardedHeaders { get; set; } = false;
    public List<string> TrustedProxyIps { get; set; } = ["127.0.0.1", "::1"];
    public string DatabasePath { get; set; } = "";
}

public sealed class TrayLiveStatusDto
{
    public string Version { get; set; } = "";
    public long UptimeSeconds { get; set; }
    public string ListenerSummary { get; set; } = "";
    public string PublicUrl { get; set; } = "";
    public string AuthMode { get; set; } = "";
    public string TlsMode { get; set; } = "";
    public string CertificateStatus { get; set; } = "";
    public string? CertificateSubject { get; set; }
    public string? CertificateThumbprint { get; set; }
    public string? CertificateExpiresUtc { get; set; }
    public int RequestsLastMinute { get; set; }
    public long TotalRequestsServed { get; set; }
    public int ActiveLongPolls { get; set; }
    public int RegisteredCarCount { get; set; }
    public int QueuedCommandCount { get; set; }
    public List<string> RecentEvents { get; set; } = [];
}

public sealed class TrayApiTokenDto
{
    public int Id { get; set; }
    public string Label { get; set; } = "";
    public string TokenPrefix { get; set; } = "";
    public int MaxCars { get; set; }
    public bool IsRevoked { get; set; }
    public long CreatedAtMs { get; set; }
    public long? LastUsedAtMs { get; set; }
}

public sealed class TrayIpcCommand
{
    public string Action { get; set; } = "";
    public TrayServerSettings? Settings { get; set; }
    public string? TokenLabel { get; set; }
    public int? MaxCars { get; set; }
    public int? TokenId { get; set; }
}

public sealed class TrayIpcResponse
{
    public bool Ok { get; set; }
    public string? Message { get; set; }
    public bool RequiresServiceRestart { get; set; }
    public TrayLiveStatusDto? Status { get; set; }
    public TrayServerSettings? Settings { get; set; }
    public List<TrayApiTokenDto>? ApiTokens { get; set; }
    public string? CreatedPlainToken { get; set; }
}

internal static class AdminIpcClient
{
    public const string PipeName = "DigitalConnectPlus.AdminIpc.v1";
    public const string ServiceName = "DigitalConnectPlusService";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private static readonly JsonSerializerOptions LineJsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    public static string GetDataDirectory()
    {
        string? env = Environment.GetEnvironmentVariable("DCP_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(env))
            return Path.GetFullPath(env);
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DigitalConnectPlus");
    }

    public static string GetConfigFilePath() =>
        Path.Combine(GetDataDirectory(), "config", "settings.json");

    public static bool IsCurrentProcessAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void RelaunchAsAdmin()
    {
        string? exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe)) return;

        var psi = new ProcessStartInfo(exe, "--open")
        {
            UseShellExecute = true,
            Verb = "runas"
        };
        try
        {
            Process.Start(psi);
            Application.Exit();
        }
        catch
        {
            // User declined UAC prompt
        }
    }

    public static async Task<TrayIpcResponse?> SendAsync(TrayIpcCommand cmd, int timeoutMs = 3000)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var cts = new CancellationTokenSource(timeoutMs);
            await pipe.ConnectAsync(cts.Token);

            await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 16_384, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 16_384, leaveOpen: true);

            string reqLine = JsonSerializer.Serialize(cmd, LineJsonOpts);
            await writer.WriteLineAsync(reqLine);

            string? respLine = await reader.ReadLineAsync(cts.Token);
            if (string.IsNullOrWhiteSpace(respLine))
                return null;

            return JsonSerializer.Deserialize<TrayIpcResponse>(respLine, LineJsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static TrayServerSettings LoadSettingsFallbackFromDisk()
    {
        string path = GetConfigFilePath();
        if (File.Exists(path))
        {
            try
            {
                string raw = File.ReadAllText(path, Encoding.UTF8);
                TrayServerSettings? parsed = JsonSerializer.Deserialize<TrayServerSettings>(raw, JsonOpts);
                if (parsed != null)
                    return parsed;
            }
            catch { }
        }
        return new TrayServerSettings
        {
            ServerSharedToken = GenerateRandomToken()
        };
    }

    public static void SaveSettingsDirectToDisk(TrayServerSettings settings)
    {
        string path = GetConfigFilePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (string.IsNullOrWhiteSpace(settings.ServerSharedToken))
            settings.ServerSharedToken = GenerateRandomToken();

        string json = JsonSerializer.Serialize(settings, JsonOpts);
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, json, new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }

    public static string GenerateRandomToken()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string ProtectPasswordForLocalMachine(string plain)
    {
        if (string.IsNullOrEmpty(plain)) return "";
        byte[] encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(plain), null, DataProtectionScope.LocalMachine);
        return Convert.ToBase64String(encrypted);
    }

    public static (bool Installed, ServiceControllerStatus? Status) QueryServiceState()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            return (true, sc.Status);
        }
        catch
        {
            return (false, null);
        }
    }

    public static async Task<(bool Ok, string Message)> ControlWindowsServiceAsync(string action)
    {
        if (!IsCurrentProcessAdmin())
        {
            // Invoke elevated sc.exe helper so standard user tray can trigger UAC cleanly
            string args = action switch
            {
                "start" => $"start {ServiceName}",
                "stop" => $"stop {ServiceName}",
                "restart" => $"/c sc stop {ServiceName} & timeout /t 2 /nobreak >nul & sc start {ServiceName}",
                _ => ""
            };
            string file = action == "restart" ? "cmd.exe" : "sc.exe";
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using Process? proc = Process.Start(psi);
                if (proc != null)
                    await proc.WaitForExitAsync();
                return (true, $"Requested service {action}.");
            }
            catch (Exception ex)
            {
                return (false, $"Service action canceled or failed: {ex.Message}");
            }
        }

        return await Task.Run(() =>
        {
            try
            {
                using var sc = new ServiceController(ServiceName);
                if (action is "stop" or "restart")
                {
                    if (sc.Status is not ServiceControllerStatus.Stopped and not ServiceControllerStatus.StopPending)
                    {
                        sc.Stop();
                    }
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                }

                if (action is "start" or "restart")
                {
                    sc.Refresh();
                    if (sc.Status == ServiceControllerStatus.Stopped)
                    {
                        sc.Start();
                    }
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
                }

                return (true, $"Service {action} completed successfully.");
            }
            catch (Exception ex)
            {
                return (false, $"Service {action} error: {ex.Message}");
            }
        });
    }
}
