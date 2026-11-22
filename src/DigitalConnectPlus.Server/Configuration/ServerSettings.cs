using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DigitalConnectPlus.Server.Configuration;

public enum NormalizedAuthMode
{
    OpenDevicePopOnly,
    SharedToken,
    AccountsPlusDevicePop
}

public static class ServerConstants
{
    public const string ProductName = "Digital Connect+ Server";
    public const string WindowsServiceName = "DigitalConnectPlusService";
    public const string HealthServiceId = "gen5w-digital-control-relay";
    public const string Version = "1.0.0";
    public const string AdminPipeName = "DigitalConnectPlus.AdminIpc.v1";

    public const int DefaultMaxBodyBytes = 262_144; // 256 KB (matches client MAX_HTTP_BYTES)
    public const long DefaultClockSkewMs = 90_000;  // ±90 seconds
    public const long MaxCommandTtlMs = 305_000;    // 300s nominal + 5s tolerance
    public const long NonceWindowMs = 300_000;      // 5-minute replay cache
    public const long NoncePruneAgeMs = 600_000;    // 10-minute DB prune
    public const long TerminalCommandRetentionMs = 86_400_000; // 24 hours
    public const int MaxLongPollWaitSeconds = 15;
    public const int DefaultLongPollWaitSeconds = 12;
}

public sealed class ServerSettings
{
    /// <summary>
    /// Public domain or HTTPS URL purchased/configured by the operator (e.g. "https://relay.mydomain.com").
    /// MUST start completely blank by default — never pre-filled with any domain.
    /// </summary>
    public string PublicUrl { get; set; } = "";

    /// <summary>
    /// "Kestrel" (direct IP/interface + port listener) or "HttpSys" (Windows kernel URL binding, can share port 443 with IIS).
    /// </summary>
    public string ListenerEngine { get; set; } = "Kestrel";

    /// <summary>
    /// IP address / interface for Kestrel to bind on: "0.0.0.0" (all IPv4), "::" (dual-stack IPv6+IPv4),
    /// "127.0.0.1" (loopback for reverse proxy), or a specific local NIC IP (e.g. "10.0.1.72").
    /// </summary>
    public string ListenInterface { get; set; } = "0.0.0.0";

    /// <summary>
    /// Primary listener port (HTTPS in TLS modes, HTTP in ReverseProxyHttp mode).
    /// </summary>
    public int Port { get; set; } = 8443;

    /// <summary>
    /// Optional HTTP port (typically 80) dedicated to Let's Encrypt HTTP-01 ACME challenges and /api/v1/health.
    /// Never redirects /api/v1/* routes.
    /// </summary>
    public bool EnableHttpAcmeListener { get; set; } = false;
    public int HttpAcmePort { get; set; } = 80;

    /// <summary>
    /// Optional explicit URL prefix(es) when using HttpSys or custom URL binding (e.g. "https://my.domain.com:443/").
    /// Starts blank.
    /// </summary>
    public string CustomBindUrl { get; set; } = "";

    /// <summary>
    /// TLS source: "WindowsCertStore" | "LetsEncrypt" | "PfxFile" | "SelfSignedLocal" | "ReverseProxyHttp"
    /// </summary>
    public string TlsMode { get; set; } = "WindowsCertStore";

    // Windows Certificate Store options
    public string WindowsCertStoreLocation { get; set; } = "LocalMachine"; // LocalMachine | CurrentUser
    public string WindowsCertStoreName { get; set; } = "My";               // My | WebHosting
    public string WindowsCertThumbprint { get; set; } = "";
    public bool AutoMatchCertByPublicUrlHost { get; set; } = true;

    // PFX file options
    public string PfxFilePath { get; set; } = "";
    public string PfxPasswordProtectedBase64 { get; set; } = "";
    public string PfxPasswordPlain { get; set; } = ""; // Optional headless/env fallback

    // Built-in Let's Encrypt ACMEv2 Auto-Renewal options
    public string LetsEncryptEmail { get; set; } = "";
    public bool LetsEncryptUseStaging { get; set; } = false;
    public bool LetsEncryptAutoRenew { get; set; } = true;
    public int LetsEncryptRenewDaysBeforeExpiry { get; set; } = 30;
    public bool LetsEncryptImportToWindowsStore { get; set; } = false;

    /// <summary>
    /// Operator Access Mode:
    /// - "device_pop_only" / "open": Pure Zero-Trust ECDSA PoP + Car PairingGrant (default personal server mode).
    /// - "shared_token": Require Authorization: Bearer &lt;ServerSharedToken&gt; + ECDSA PoP.
    /// - "account_plus_device_pop" / "accounts": Per-user accounts (/api/v1/auth/*) &amp; API tokens + car quotas + ECDSA PoP.
    /// </summary>
    public string AuthMode { get; set; } = "device_pop_only";

    public string ServerSharedToken { get; set; } = "";

    // Multi-user account settings
    public bool AllowPublicAccountRegistration { get; set; } = true;
    public int MaxCarsPerAccount { get; set; } = 5;
    public int TokenLifetimeDays { get; set; } = 30;
    public string JwtIssuer { get; set; } = "digital-connect-plus";
    public string JwtAudience { get; set; } = "gen5w-digital-control";

    // Relay limits & rate limiting
    public int MaxQueuedCommandsPerCar { get; set; } = 20;
    public int RateLimitPerIpPerMinute { get; set; } = 100;
    public int RateLimitPerCarPerMinute { get; set; } = 40;
    public int MaxRequestBodyBytes { get; set; } = ServerConstants.DefaultMaxBodyBytes;

    // Reverse proxy client IP forwarding
    public bool TrustForwardedHeaders { get; set; } = false;
    public List<string> TrustedProxyIps { get; set; } = ["127.0.0.1", "::1"];

    // Custom DB path override (leave empty to use DataDirectory/data/digitalconnect.db)
    public string DatabasePath { get; set; } = "";

    [JsonIgnore]
    public NormalizedAuthMode NormalizedAuth => NormalizeAuthMode(AuthMode);

    public static NormalizedAuthMode NormalizeAuthMode(string? raw)
    {
        string mode = (raw ?? "").Trim().ToLowerInvariant();
        return mode switch
        {
            "open" or "device_pop_only" or "pop" or "" => NormalizedAuthMode.OpenDevicePopOnly,
            "shared_token" or "shared" or "token" => NormalizedAuthMode.SharedToken,
            "accounts" or "account_plus_device_pop" or "account" => NormalizedAuthMode.AccountsPlusDevicePop,
            _ => NormalizedAuthMode.OpenDevicePopOnly
        };
    }

    public string? TryGetPublicHostname()
    {
        string raw = (PublicUrl ?? "").Trim();
        if (string.IsNullOrEmpty(raw))
            return null;

        if (Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri) && !string.IsNullOrWhiteSpace(uri.Host))
            return uri.Host.ToLowerInvariant();

        // Allow bare domain input like "relay.mydomain.com"
        if (!raw.Contains('/') && !raw.Contains(' ') && Uri.CheckHostName(raw) != UriHostNameType.Unknown)
            return raw.ToLowerInvariant();

        return null;
    }

    public static string GenerateSecureToken(int byteCount = 32)
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(byteCount);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public ServerSettings Clone()
    {
        string json = JsonSerializer.Serialize(this);
        return JsonSerializer.Deserialize<ServerSettings>(json) ?? new ServerSettings();
    }
}
