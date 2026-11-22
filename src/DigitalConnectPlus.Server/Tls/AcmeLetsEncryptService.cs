using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Services;

namespace DigitalConnectPlus.Server.Tls;

public sealed class AcmeChallengeStore
{
    private readonly ConcurrentDictionary<string, string> _tokens = new(StringComparer.Ordinal);

    public void SetChallenge(string token, string keyAuthorization) => _tokens[token] = keyAuthorization;
    public void RemoveChallenge(string token) => _tokens.TryRemove(token, out _);
    public bool TryGetKeyAuthorization(string token, out string keyAuth) => _tokens.TryGetValue(token, out keyAuth!);
}

/// <summary>
/// Built-in RFC 8555 ACMEv2 client for automatic Let's Encrypt issuance &amp; renewal (HTTP-01 challenge).
/// Issues NIST P-256 certificates with full ISRG intermediate chain for Gen5W Android 4.4.2 + modern TLS 1.2/1.3.
/// </summary>
public sealed class AcmeLetsEncryptService : BackgroundService
{
    private const string ProductionDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory";
    private const string StagingDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

    private readonly SettingsManager _settings;
    private readonly CertificateProvider _certProvider;
    private readonly AcmeChallengeStore _challengeStore;
    private readonly MetricsTracker _metrics;
    private readonly ILogger<AcmeLetsEncryptService> _logger;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _renewLock = new(1, 1);

    private string? _cachedNonce;

    public AcmeLetsEncryptService(
        SettingsManager settings,
        CertificateProvider certProvider,
        AcmeChallengeStore challengeStore,
        MetricsTracker metrics,
        ILogger<AcmeLetsEncryptService> logger)
    {
        _settings = settings;
        _certProvider = certProvider;
        _challengeStore = challengeStore;
        _metrics = metrics;
        _logger = logger;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(45) };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DigitalConnectPlusServer", ServerConstants.Version));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial startup check after listener comes online
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(8), stoppingToken);
            await CheckAndAutoRenewIfDueAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Initial Let's Encrypt auto-renew check encountered an error.");
        }

        using var timer = new PeriodicTimer(TimeSpan.FromHours(12));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await CheckAndAutoRenewIfDueAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Periodic Let's Encrypt auto-renew check failed.");
            }
        }
    }

    public async Task CheckAndAutoRenewIfDueAsync(CancellationToken ct = default)
    {
        ServerSettings s = _settings.Current;
        if (!string.Equals(s.TlsMode, "LetsEncrypt", StringComparison.OrdinalIgnoreCase) || !s.LetsEncryptAutoRenew)
            return;

        string? domain = s.TryGetPublicHostname();
        if (string.IsNullOrWhiteSpace(domain))
            return;

        CertificateSnapshot? snap = _certProvider.CurrentSnapshot;
        int renewDays = Math.Clamp(s.LetsEncryptRenewDaysBeforeExpiry, 5, 60);

        bool hasValidLetsEncryptCert =
            snap != null &&
            snap.SourceDescription.Contains("Let's Encrypt", StringComparison.OrdinalIgnoreCase) &&
            CertificateProvider.MatchesHostName(snap.Certificate, domain) &&
            snap.NotAfterUtc > DateTime.UtcNow.AddDays(renewDays);

        if (hasValidLetsEncryptCert)
            return;

        _metrics.LogEvent("ACME", $"Auto-renewing Let's Encrypt certificate for '{domain}'...");
        var (ok, message) = await IssueOrRenewNowAsync(force: false, ct);
        _metrics.LogEvent("ACME", ok ? message : $"Auto-renew failed: {message}");
    }

    public async Task<(bool Ok, string Message)> IssueOrRenewNowAsync(bool force, CancellationToken ct = default)
    {
        if (!await _renewLock.WaitAsync(TimeSpan.FromSeconds(2), ct))
            return (false, "Another Let's Encrypt operation is already in progress.");

        string? activeToken = null;
        try
        {
            ServerSettings s = _settings.Current;
            string? domain = s.TryGetPublicHostname();
            if (string.IsNullOrWhiteSpace(domain))
                return (false, "Public Domain / URL is blank. Enter your purchased domain before requesting a Let's Encrypt certificate.");

            if (domain is "localhost" || Uri.CheckHostName(domain) != UriHostNameType.Dns || !domain.Contains('.'))
                return (false, $"'{domain}' is not a public DNS domain eligible for Let's Encrypt.");

            string directoryUrl = s.LetsEncryptUseStaging ? StagingDirectoryUrl : ProductionDirectoryUrl;
            _metrics.LogEvent("ACME", $"Contacting Let's Encrypt ({(s.LetsEncryptUseStaging ? "Staging" : "Production")}) for {domain}...");

            using JsonDocument dirDoc = JsonDocument.Parse(await _http.GetStringAsync(directoryUrl, ct));
            JsonElement dirRoot = dirDoc.RootElement;
            string newNonceUrl = dirRoot.GetProperty("newNonce").GetString()!;
            string newAccountUrl = dirRoot.GetProperty("newAccount").GetString()!;
            string newOrderUrl = dirRoot.GetProperty("newOrder").GetString()!;

            using ECDsa accountKey = LoadOrCreateAccountKey(s.LetsEncryptUseStaging);
            string jwkThumbprint = ComputeJwkThumbprint(accountKey, out object jwkObject);

            // 1. Register / Lookup ACME Account
            object accountPayload = string.IsNullOrWhiteSpace(s.LetsEncryptEmail)
                ? new { termsOfServiceAgreed = true }
                : new { termsOfServiceAgreed = true, contact = new[] { $"mailto:{s.LetsEncryptEmail.Trim()}" } };

            var (acctResp, acctBody) = await SendSignedJwsAsync(
                newAccountUrl, newNonceUrl, accountKey, kid: null, jwk: jwkObject, payload: accountPayload, ct);

            string? kid = acctResp.Headers.Location?.ToString();
            if (string.IsNullOrEmpty(kid))
                return (false, $"ACME account registration did not return Location header: {acctBody}");

            // 2. Create New Order for domain
            var orderPayload = new
            {
                identifiers = new[] { new { type = "dns", value = domain } }
            };
            var (orderResp, orderBody) = await SendSignedJwsAsync(
                newOrderUrl, newNonceUrl, accountKey, kid: kid, jwk: null, payload: orderPayload, ct);

            string? orderUrl = orderResp.Headers.Location?.ToString();
            using JsonDocument orderDoc = JsonDocument.Parse(orderBody);
            string finalizeUrl = orderDoc.RootElement.GetProperty("finalize").GetString()!;
            string authzUrl = orderDoc.RootElement.GetProperty("authorizations")[0].GetString()!;

            // 3. Fetch HTTP-01 Challenge
            var (_, authzBody) = await SendSignedJwsAsync(
                authzUrl, newNonceUrl, accountKey, kid: kid, jwk: null, payload: null, ct);

            using JsonDocument authzDoc = JsonDocument.Parse(authzBody);
            string authzStatus = authzDoc.RootElement.GetProperty("status").GetString() ?? "";

            if (!string.Equals(authzStatus, "valid", StringComparison.OrdinalIgnoreCase))
            {
                string? challengeUrl = null;
                foreach (JsonElement ch in authzDoc.RootElement.GetProperty("challenges").EnumerateArray())
                {
                    if (string.Equals(ch.GetProperty("type").GetString(), "http-01", StringComparison.OrdinalIgnoreCase))
                    {
                        activeToken = ch.GetProperty("token").GetString()!;
                        challengeUrl = ch.GetProperty("url").GetString()!;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(activeToken) || string.IsNullOrEmpty(challengeUrl))
                    return (false, "Let's Encrypt did not offer an HTTP-01 challenge for this domain.");

                string keyAuthorization = $"{activeToken}.{jwkThumbprint}";
                _challengeStore.SetChallenge(activeToken, keyAuthorization);

                // Notify Let's Encrypt challenge is ready
                await SendSignedJwsAsync(
                    challengeUrl, newNonceUrl, accountKey, kid: kid, jwk: null, payload: new { }, ct);

                // Poll authorization until valid (up to 60s)
                for (int attempt = 0; attempt < 20; attempt++)
                {
                    await Task.Delay(TimeSpan.FromSeconds(3), ct);
                    var (_, pollAuthzBody) = await SendSignedJwsAsync(
                        authzUrl, newNonceUrl, accountKey, kid: kid, jwk: null, payload: null, ct);

                    using JsonDocument pollDoc = JsonDocument.Parse(pollAuthzBody);
                    string st = pollDoc.RootElement.GetProperty("status").GetString() ?? "";
                    if (string.Equals(st, "valid", StringComparison.OrdinalIgnoreCase))
                    {
                        authzStatus = "valid";
                        break;
                    }
                    if (string.Equals(st, "invalid", StringComparison.OrdinalIgnoreCase))
                    {
                        return (false, $"HTTP-01 validation failed (ensure port 80 reaches this server for {domain}): {pollAuthzBody}");
                    }
                }

                if (!string.Equals(authzStatus, "valid", StringComparison.OrdinalIgnoreCase))
                    return (false, "Timed out waiting for Let's Encrypt HTTP-01 challenge validation.");
            }

            // 4. Generate NIST P-256 Certificate Key + CSR & Finalize Order
            using ECDsa certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csrReq = new CertificateRequest($"CN={domain}", certKey, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(domain);
            csrReq.CertificateExtensions.Add(san.Build());

            byte[] csrDer = csrReq.CreateSigningRequest();
            var (_, finBody) = await SendSignedJwsAsync(
                finalizeUrl, newNonceUrl, accountKey, kid: kid, jwk: null,
                payload: new { csr = Base64UrlEncode(csrDer) }, ct);

            string? certDownloadUrl = null;
            using (JsonDocument finDoc = JsonDocument.Parse(finBody))
            {
                if (finDoc.RootElement.TryGetProperty("certificate", out JsonElement cEl))
                    certDownloadUrl = cEl.GetString();
            }

            if (string.IsNullOrEmpty(certDownloadUrl) && !string.IsNullOrEmpty(orderUrl))
            {
                for (int attempt = 0; attempt < 15; attempt++)
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), ct);
                    var (_, pollOrderBody) = await SendSignedJwsAsync(
                        orderUrl, newNonceUrl, accountKey, kid: kid, jwk: null, payload: null, ct);
                    using JsonDocument poDoc = JsonDocument.Parse(pollOrderBody);
                    if (poDoc.RootElement.TryGetProperty("certificate", out JsonElement cEl))
                    {
                        certDownloadUrl = cEl.GetString();
                        if (!string.IsNullOrEmpty(certDownloadUrl))
                            break;
                    }
                }
            }

            if (string.IsNullOrEmpty(certDownloadUrl))
                return (false, "Order finalized, but Let's Encrypt certificate URL was not ready in time.");

            // 5. Download Full PEM Certificate Chain (Leaf + Intermediate CA for Android 4.4.2 KitKat)
            var (_, pemChain) = await SendSignedJwsAsync(
                certDownloadUrl, newNonceUrl, accountKey, kid: kid, jwk: null, payload: null, ct,
                acceptHeader: "application/pem-certificate-chain");

            var pemCerts = new X509Certificate2Collection();
            pemCerts.ImportFromPem(pemChain);
            if (pemCerts.Count == 0)
                return (false, "Downloaded Let's Encrypt PEM bundle contained no certificates.");

            using X509Certificate2 leafWithKey = pemCerts[0].CopyWithPrivateKey(certKey);
            var fullExportCollection = new X509Certificate2Collection { leafWithKey };
            for (int i = 1; i < pemCerts.Count; i++)
                fullExportCollection.Add(pemCerts[i]);

            byte[] pfxBytes = fullExportCollection.Export(X509ContentType.Pfx, "")
                ?? throw new InvalidOperationException("Failed to export PFX bundle.");

            string pfxPath = _certProvider.GetLetsEncryptPfxPath();
            string tmpPath = pfxPath + ".tmp";
            await File.WriteAllBytesAsync(tmpPath, pfxBytes, ct);
            File.Move(tmpPath, pfxPath, overwrite: true);

            if (s.LetsEncryptImportToWindowsStore && OperatingSystem.IsWindows())
            {
                TryImportIntoWindowsMachineStore(pfxBytes, domain);
            }

            _certProvider.ActivateNewlyIssuedPfx(pfxPath, "", "Let's Encrypt Auto-Renew");
            return (true, $"Successfully issued & activated Let's Encrypt certificate for '{domain}' (expires {leafWithKey.NotAfter:yyyy-MM-dd}).");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Let's Encrypt ACMEv2 issuance error.");
            return (false, ex.Message);
        }
        finally
        {
            if (activeToken != null)
                _challengeStore.RemoveChallenge(activeToken);
            _renewLock.Release();
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void TryImportIntoWindowsMachineStore(byte[] pfxBytes, string domain)
    {
        try
        {
            X509Certificate2Collection col = CertificateProvider.LoadPkcs12CollectionSchannelSafe(pfxBytes, "");
            X509Certificate2? leaf = col.FirstOrDefault(c => c.HasPrivateKey);
            if (leaf == null) return;
            leaf.FriendlyName = $"Digital Connect+ ({domain})";

            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(leaf);
        }
        catch
        {
            // Non-fatal if running without LocalMachine Cert Store write privilege
        }
    }

    private ECDsa LoadOrCreateAccountKey(bool staging)
    {
        string fileName = staging ? "acme-account-staging.pem" : "acme-account-prod.pem";
        string path = Path.Combine(_settings.AcmeDirectory, fileName);

        if (File.Exists(path))
        {
            string pem = File.ReadAllText(path, Encoding.UTF8);
            var existing = ECDsa.Create();
            existing.ImportFromPem(pem);
            return existing;
        }

        var created = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string exportedPem = created.ExportECPrivateKeyPem();
        File.WriteAllText(path, exportedPem, new UTF8Encoding(false));
        return created;
    }

    private static string ComputeJwkThumbprint(ECDsa key, out object jwkObject)
    {
        ECParameters p = key.ExportParameters(false);
        string x = Base64UrlEncode(p.Q.X!);
        string y = Base64UrlEncode(p.Q.Y!);
        jwkObject = new { crv = "P-256", kty = "EC", x, y };

        // RFC 7638 canonical JSON: exact lexicographical member order with zero whitespace
        string canonicalJwk = $"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJwk));
        return Base64UrlEncode(hash);
    }

    private async Task<(HttpResponseMessage Response, string Body)> SendSignedJwsAsync(
        string url,
        string newNonceUrl,
        ECDsa accountKey,
        string? kid,
        object? jwk,
        object? payload, // null => POST-as-GET ("")
        CancellationToken ct,
        string acceptHeader = "application/json")
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            string nonce = await AcquireNonceAsync(newNonceUrl, ct);

            object protectedObj = kid != null
                ? new { alg = "ES256", kid, nonce, url }
                : new { alg = "ES256", jwk, nonce, url };

            string protectedB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(protectedObj)));
            string payloadB64 = payload == null
                ? ""
                : Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

            byte[] signingInput = Encoding.ASCII.GetBytes($"{protectedB64}.{payloadB64}");
            // RFC 7518 §3.4: JWS ES256 requires raw 64-byte IEEE P1363 concatenation (r || s)
            byte[] sigBytes = accountKey.SignData(signingInput, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            string sigB64 = Base64UrlEncode(sigBytes);

            string jwsJson = JsonSerializer.Serialize(new
            {
                @protected = protectedB64,
                payload = payloadB64,
                signature = sigB64
            });

            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(jwsJson, Encoding.UTF8, "application/jose+json")
            };
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptHeader));

            HttpResponseMessage resp = await _http.SendAsync(req, ct);
            if (resp.Headers.TryGetValues("Replay-Nonce", out var nonces))
                _cachedNonce = nonces.FirstOrDefault();

            string body = await resp.Content.ReadAsStringAsync(ct);
            if (resp.IsSuccessStatusCode)
                return (resp, body);

            if (attempt == 0 && body.Contains("badNonce", StringComparison.OrdinalIgnoreCase))
            {
                _cachedNonce = null;
                resp.Dispose();
                continue;
            }

            resp.Dispose();
            throw new InvalidOperationException($"ACME request to {url} failed ({(int)resp.StatusCode}): {body}");
        }

        throw new InvalidOperationException("Failed to obtain a valid ACME Replay-Nonce.");
    }

    private async Task<string> AcquireNonceAsync(string newNonceUrl, CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(_cachedNonce))
        {
            string n = _cachedNonce;
            _cachedNonce = null;
            return n;
        }

        using var req = new HttpRequestMessage(HttpMethod.Head, newNonceUrl);
        using HttpResponseMessage resp = await _http.SendAsync(req, ct);
        if (resp.Headers.TryGetValues("Replay-Nonce", out var values))
        {
            string? nonce = values.FirstOrDefault();
            if (!string.IsNullOrEmpty(nonce))
                return nonce;
        }
        throw new InvalidOperationException("Let's Encrypt directory did not return a Replay-Nonce header.");
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
