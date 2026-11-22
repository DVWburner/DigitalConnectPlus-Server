using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Services;

namespace DigitalConnectPlus.Server.Tls;

public sealed record CertificateSnapshot(
    X509Certificate2 Certificate,
    SslStreamCertificateContext Context,
    string SourceDescription,
    string Subject,
    string Thumbprint,
    DateTime NotAfterUtc);

/// <summary>
/// Manages TLS certificates from Windows Certificate Store, Let's Encrypt ACMEv2, PFX files,
/// or explicit local self-signed certs, with zero-downtime hot reload and Android 4.4.2 TLS 1.2 + 1.3 support.
/// </summary>
public sealed class CertificateProvider : IDisposable
{
    private readonly SettingsManager _settings;
    private readonly MetricsTracker _metrics;
    private readonly ILogger<CertificateProvider> _logger;
    private readonly object _sync = new();

    private CertificateSnapshot? _active;
    private DateTimeOffset _lastStoreRefreshUtc = DateTimeOffset.MinValue;

    public CertificateProvider(
        SettingsManager settings,
        MetricsTracker metrics,
        ILogger<CertificateProvider> logger)
    {
        _settings = settings;
        _metrics = metrics;
        _logger = logger;
    }

    public CertificateSnapshot? CurrentSnapshot
    {
        get
        {
            lock (_sync)
            {
                return _active;
            }
        }
    }

    public string StatusMessage { get; private set; } = "Not initialized";

    public string GetLetsEncryptPfxPath() =>
        Path.Combine(_settings.CertsDirectory, "letsencrypt-current.pfx");

    public string GetSelfSignedPfxPath() =>
        Path.Combine(_settings.CertsDirectory, "local-selfsigned.pfx");

    public SslServerAuthenticationOptions GetSslServerOptions(string? sniHostName)
    {
        // Periodically check Windows Cert Store every 10 minutes so external tools (win-acme / CertifyTheWeb)
        // that renew a cert in LocalMachine\My are picked up automatically with zero downtime.
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (now - _lastStoreRefreshUtc > TimeSpan.FromMinutes(10))
        {
            _lastStoreRefreshUtc = now;
            if (string.Equals(_settings.Current.TlsMode, "WindowsCertStore", StringComparison.OrdinalIgnoreCase))
            {
                try { ReloadCertificate(); } catch { }
            }
        }

        CertificateSnapshot? snap = CurrentSnapshot;
        if (snap == null)
            throw new InvalidOperationException($"No active TLS certificate loaded ({StatusMessage}). Configure a certificate in Digital Connect+ Server settings.");

        return new SslServerAuthenticationOptions
        {
            ServerCertificateContext = snap.Context,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ClientCertificateRequired = false,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };
    }

    public bool ReloadCertificate()
    {
        ServerSettings s = _settings.Current;
        string mode = (s.TlsMode ?? "WindowsCertStore").Trim();

        if (string.Equals(mode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase))
        {
            SwapSnapshot(null, "HTTP Reverse Proxy Mode (TLS terminated upstream)");
            return true;
        }

        try
        {
            CertificateSnapshot? loaded = mode.ToLowerInvariant() switch
            {
                "windowscertstore" => TryLoadFromWindowsStore(s),
                "letsencrypt" => TryLoadFromLetsEncryptOrFallback(s),
                "pfxfile" => TryLoadFromPfxFile(s),
                "selfsignedlocal" => LoadOrCreateSelfSigned(s),
                _ => TryLoadFromWindowsStore(s)
            };

            if (loaded != null)
            {
                SwapSnapshot(loaded, $"Active ({loaded.SourceDescription}) — expires {loaded.NotAfterUtc:yyyy-MM-dd}");
                return true;
            }

            // If LetsEncrypt or WindowsCertStore doesn't have a cert yet (e.g. fresh install with blank URL before user configures domain),
            // generate an ephemeral bootstrap self-signed cert so Kestrel can start cleanly and wait for user configuration or ACME HTTP-01!
            CertificateSnapshot bootstrap = LoadOrCreateSelfSigned(s, isBootstrapFallback: true);
            string reason = string.IsNullOrWhiteSpace(s.PublicUrl)
                ? "Awaiting domain configuration (temporary bootstrap cert active)"
                : $"Configured {mode} cert not found yet (temporary bootstrap cert active)";
            SwapSnapshot(bootstrap, reason);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Certificate reload failed for mode {TlsMode}", mode);
            StatusMessage = $"Error loading {mode}: {ex.Message}";
            _metrics.LogEvent("TLS", StatusMessage);
            return false;
        }
    }

    public void ActivateNewlyIssuedPfx(string pfxPath, string password, string sourceLabel)
    {
        CertificateSnapshot snap = LoadPkcs12BundleWithChain(pfxPath, password, sourceLabel);
        SwapSnapshot(snap, $"Active ({sourceLabel}) — expires {snap.NotAfterUtc:yyyy-MM-dd}");
    }

    private CertificateSnapshot? TryLoadFromWindowsStore(ServerSettings s)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        StoreLocation loc = string.Equals(s.WindowsCertStoreLocation, "CurrentUser", StringComparison.OrdinalIgnoreCase)
            ? StoreLocation.CurrentUser
            : StoreLocation.LocalMachine;

        string storeName = string.IsNullOrWhiteSpace(s.WindowsCertStoreName) ? "My" : s.WindowsCertStoreName.Trim();
        using var store = new X509Store(storeName, loc);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        X509Certificate2? best = null;
        string cleanThumb = (s.WindowsCertThumbprint ?? "").Replace(" ", "").Replace(":", "").Trim();

        if (!string.IsNullOrEmpty(cleanThumb))
        {
            X509Certificate2Collection matches = store.Certificates.Find(X509FindType.FindByThumbprint, cleanThumb, validOnly: false);
            best = matches
                .Where(c => c.HasPrivateKey)
                .OrderByDescending(c => c.NotAfter)
                .FirstOrDefault();
        }

        if (best == null && s.AutoMatchCertByPublicUrlHost)
        {
            string? host = s.TryGetPublicHostname();
            if (!string.IsNullOrEmpty(host))
            {
                DateTime now = DateTime.UtcNow;
                best = store.Certificates
                    .Where(c => c.HasPrivateKey && c.NotAfter.ToUniversalTime() > now && MatchesHostName(c, host))
                    .OrderByDescending(c => c.NotAfter)
                    .FirstOrDefault();
            }
        }

        if (best == null)
            return null;

        // Clone cert reference so closing X509Store doesn't invalidate it
        var persisted = new X509Certificate2(best);
        var intermediates = new X509Certificate2Collection();
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(persisted);
            for (int i = 1; i < chain.ChainElements.Count - 1; i++)
            {
                intermediates.Add(new X509Certificate2(chain.ChainElements[i].Certificate));
            }
        }

        var ctx = SslStreamCertificateContext.Create(persisted, intermediates, offline: true);
        return new CertificateSnapshot(
            persisted,
            ctx,
            $"Windows Store {loc}\\{storeName}",
            persisted.Subject,
            persisted.Thumbprint,
            persisted.NotAfter.ToUniversalTime());
    }

    private CertificateSnapshot? TryLoadFromLetsEncryptOrFallback(ServerSettings s)
    {
        string pfxPath = GetLetsEncryptPfxPath();
        if (!File.Exists(pfxPath))
            return null;

        return LoadPkcs12BundleWithChain(pfxPath, "", "Let's Encrypt Auto-Renew");
    }

    private CertificateSnapshot? TryLoadFromPfxFile(ServerSettings s)
    {
        if (string.IsNullOrWhiteSpace(s.PfxFilePath) || !File.Exists(s.PfxFilePath))
            return null;

        string pwd = SettingsManager.UnprotectStringFromLocalMachine(s.PfxPasswordProtectedBase64, s.PfxPasswordPlain);
        return LoadPkcs12BundleWithChain(s.PfxFilePath, pwd, $"PFX ({Path.GetFileName(s.PfxFilePath)})");
    }

    private CertificateSnapshot LoadPkcs12BundleWithChain(string pfxPath, string password, string sourceLabel)
    {
        byte[] rawPfx = File.ReadAllBytes(pfxPath);
        X509Certificate2Collection collection = LoadPkcs12CollectionSchannelSafe(rawPfx, password);

        X509Certificate2? leaf = collection.FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new InvalidOperationException("PFX file does not contain a certificate with a private key.");

        var additional = new X509Certificate2Collection();
        foreach (X509Certificate2 cert in collection)
        {
            if (!string.Equals(cert.Thumbprint, leaf.Thumbprint, StringComparison.OrdinalIgnoreCase))
                additional.Add(cert);
        }

        var ctx = SslStreamCertificateContext.Create(leaf, additional, offline: true);
        return new CertificateSnapshot(
            leaf,
            ctx,
            sourceLabel,
            leaf.Subject,
            leaf.Thumbprint,
            leaf.NotAfter.ToUniversalTime());
    }

    private CertificateSnapshot LoadOrCreateSelfSigned(ServerSettings s, bool isBootstrapFallback = false)
    {
        string pfxPath = GetSelfSignedPfxPath();
        string? configuredHost = s.TryGetPublicHostname();

        if (File.Exists(pfxPath))
        {
            try
            {
                CertificateSnapshot existing = LoadPkcs12BundleWithChain(
                    pfxPath,
                    "",
                    isBootstrapFallback ? "Bootstrap Self-Signed" : "Local Self-Signed");

                if (existing.NotAfterUtc > DateTime.UtcNow.AddDays(7) &&
                    (string.IsNullOrEmpty(configuredHost) || MatchesHostName(existing.Certificate, configuredHost)))
                {
                    return existing;
                }
            }
            catch { }
        }

        // Generate ECDSA NIST P-256 certificate (compatible with Gen5W Android 4.4.2 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string subjectCn = !string.IsNullOrEmpty(configuredHost) ? configuredHost : "DigitalConnectPlus-Local";
        var req = new CertificateRequest($"CN={subjectCn}", key, HashAlgorithmName.SHA256);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")], // Server Authentication
            false));

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.IPv6Loopback);
        if (!string.IsNullOrEmpty(configuredHost))
            san.AddDnsName(configuredHost);
        if (IPAddress.TryParse((s.ListenInterface ?? "").Trim(), out IPAddress? listenIp) &&
            !listenIp.Equals(IPAddress.Any) && !listenIp.Equals(IPAddress.IPv6Any) && !IPAddress.IsLoopback(listenIp))
        {
            san.AddIpAddress(listenIp);
        }
        req.CertificateExtensions.Add(san.Build());

        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 ephemeral = req.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(2));
        byte[] pfxBytes = ephemeral.Export(X509ContentType.Pfx, "");
        File.WriteAllBytes(pfxPath, pfxBytes);

        return LoadPkcs12BundleWithChain(
            pfxPath,
            "",
            isBootstrapFallback ? "Bootstrap Self-Signed" : "Local Self-Signed");
    }

    public static X509Certificate2Collection LoadPkcs12CollectionSchannelSafe(byte[] pfxBytes, string? password)
    {
        if (OperatingSystem.IsWindows())
        {
            // Windows Schannel requires non-ephemeral key storage flags for TLS server certificates
            try
            {
                return X509CertificateLoader.LoadPkcs12Collection(
                    pfxBytes,
                    password,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch
            {
                return X509CertificateLoader.LoadPkcs12Collection(
                    pfxBytes,
                    password,
                    X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            }
        }

        return X509CertificateLoader.LoadPkcs12Collection(pfxBytes, password, X509KeyStorageFlags.Exportable);
    }

    public static bool MatchesHostName(X509Certificate2 cert, string host)
    {
        try
        {
            string dnsFromCert = cert.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            if (WildcardMatch(dnsFromCert, host))
                return true;

            foreach (X509Extension ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                {
                    string formatted = ext.Format(multiLine: true);
                    foreach (string line in formatted.Split(['\r', '\n', ','], StringSplitOptions.RemoveEmptyEntries))
                    {
                        int eq = line.IndexOf('=');
                        string candidate = (eq >= 0 ? line[(eq + 1)..] : line).Trim();
                        if (WildcardMatch(candidate, host))
                            return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }

    private static bool WildcardMatch(string? pattern, string host)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return false;

        if (string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase))
            return true;

        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            string suffix = pattern[1..]; // ".domain.com"
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                string prefix = host[..^suffix.Length];
                return prefix.Length > 0 && !prefix.Contains('.');
            }
        }
        return false;
    }

    private void SwapSnapshot(CertificateSnapshot? next, string statusMessage)
    {
        CertificateSnapshot? previous;
        lock (_sync)
        {
            previous = _active;
            _active = next;
            StatusMessage = statusMessage;
        }

        if (previous != null && !ReferenceEquals(previous.Certificate, next?.Certificate))
        {
            // Delay disposal briefly so in-flight TLS handshakes complete smoothly
            _ = Task.Run(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(15));
                try { previous.Certificate.Dispose(); } catch { }
            });
        }

        _metrics.LogEvent("TLS", statusMessage);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _active?.Certificate.Dispose();
            _active = null;
        }
    }
}
