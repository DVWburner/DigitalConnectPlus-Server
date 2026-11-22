using System.Collections.Concurrent;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Crypto;
using Microsoft.IdentityModel.Tokens;

namespace DigitalConnectPlus.Server.Security;

public sealed record AccountRecord(
    int Id,
    string Username,
    byte[] PasswordHash,
    byte[] PasswordSalt,
    int HashIterations,
    int MaxCars,
    int TokenVersion,
    bool IsDisabled,
    long CreatedAtMs);

public sealed record ApiTokenRecord(
    int Id,
    string Label,
    string TokenHashHex,
    string TokenPrefix,
    int? AccountId,
    int MaxCars,
    bool IsRevoked,
    long CreatedAtMs,
    long? LastUsedAtMs);

public sealed record AuthenticatedPrincipalInfo(
    int OwnerKeyId,       // Positive for AccountId, Negative (-ApiTokenId) for standalone API token
    string DisplayLabel,
    int MaxCars);

public static class PasswordHasher
{
    public const int DefaultIterations = 150_000;
    private const int SaltSize = 16;
    private const int KeySize = 32;

    public static readonly byte[] DummySalt = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
    public static readonly byte[] DummyHash = Convert.FromHexString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");

    public static (byte[] Hash, byte[] Salt, int Iterations) HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            DefaultIterations,
            HashAlgorithmName.SHA256,
            KeySize);
        return (hash, salt, DefaultIterations);
    }

    public static bool VerifyPassword(string password, byte[] expectedHash, byte[] salt, int iterations)
    {
        int safeIter = Math.Clamp(iterations, 10_000, 1_000_000);
        byte[] computed = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            safeIter,
            HashAlgorithmName.SHA256,
            expectedHash.Length);
        return CryptographicOperations.FixedTimeEquals(computed, expectedHash);
    }
}

public sealed class AccountTokenService
{
    private readonly SettingsManager _settings;
    private readonly TimeProvider _timeProvider;
    private readonly JwtSecurityTokenHandler _jwtHandler = new() { MapInboundClaims = false };
    private readonly object _keySync = new();
    private byte[] _jwtKey = [];

    public AccountTokenService(SettingsManager settings, TimeProvider timeProvider)
    {
        _settings = settings;
        _timeProvider = timeProvider;
    }

    public void InitializeSigningKey(byte[] keyBytes)
    {
        if (keyBytes.Length < 32)
            throw new ArgumentException("JWT signing key must be >= 32 bytes.", nameof(keyBytes));
        lock (_keySync)
        {
            _jwtKey = keyBytes.ToArray();
        }
    }

    public SymmetricSecurityKey GetSigningKey()
    {
        lock (_keySync)
        {
            if (_jwtKey.Length < 32)
                throw new InvalidOperationException("JWT signing key is not initialized.");
            return new SymmetricSecurityKey(_jwtKey);
        }
    }

    public (string Token, DateTimeOffset ExpiresAtUtc) IssueAccountJwt(AccountRecord account)
    {
        ServerSettings s = _settings.Current;
        DateTimeOffset now = _timeProvider.GetUtcNow();
        int days = Math.Clamp(s.TokenLifetimeDays, 1, 365);
        DateTimeOffset expiresAt = now.AddDays(days);

        Claim[] claims =
        [
            new(JwtRegisteredClaimNames.Sub, account.Id.ToString(CultureInfo.InvariantCulture)),
            new("username", account.Username),
            new("tv", account.TokenVersion.ToString(CultureInfo.InvariantCulture)),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        ];

        var creds = new SigningCredentials(GetSigningKey(), SecurityAlgorithms.HmacSha256);
        var jwt = new JwtSecurityToken(
            issuer: s.JwtIssuer,
            audience: s.JwtAudience,
            claims: claims,
            notBefore: now.AddMinutes(-1).UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: creds);

        return (_jwtHandler.WriteToken(jwt), expiresAt);
    }

    public bool TryValidateAccountJwt(string rawToken, out int accountId, out int tokenVersion)
    {
        accountId = 0;
        tokenVersion = 0;
        ServerSettings s = _settings.Current;
        DateTimeOffset now = _timeProvider.GetUtcNow();

        try
        {
            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = s.JwtIssuer,
                ValidateAudience = true,
                ValidAudience = s.JwtAudience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = GetSigningKey(),
                ValidateLifetime = true,
                LifetimeValidator = (notBefore, expires, _, _) =>
                {
                    DateTime nowUtc = now.UtcDateTime;
                    if (notBefore.HasValue && nowUtc < notBefore.Value.AddMinutes(-1))
                        return false;
                    if (expires.HasValue && nowUtc >= expires.Value.AddMinutes(1))
                        return false;
                    return expires.HasValue;
                }
            };

            ClaimsPrincipal principal = _jwtHandler.ValidateToken(rawToken, parameters, out _);
            string? sub = principal.FindFirstValue(JwtRegisteredClaimNames.Sub) ?? principal.FindFirstValue(ClaimTypes.NameIdentifier);
            string? tv = principal.FindFirstValue("tv");

            if (!int.TryParse(sub, NumberStyles.Integer, CultureInfo.InvariantCulture, out accountId) || accountId <= 0)
                return false;

            if (!int.TryParse(tv, NumberStyles.Integer, CultureInfo.InvariantCulture, out tokenVersion))
                return false;

            return true;
        }
        catch
        {
            return false;
        }
    }

    public static (string PlainToken, string TokenHashHex, string TokenPrefix) GenerateStaticApiToken()
    {
        string secret = ServerSettings.GenerateSecureToken(32);
        string plain = $"dcp_{secret}";
        string hashHex = Gen5WCrypto.Sha256HexUtf8(plain);
        string prefix = plain[..Math.Min(12, plain.Length)];
        return (plain, hashHex, prefix);
    }

    public static string HashApiToken(string plainToken) => Gen5WCrypto.Sha256HexUtf8(plainToken);

    public static bool FixedTimeVerifySharedToken(string providedToken, string expectedSharedToken)
    {
        if (string.IsNullOrEmpty(providedToken) || string.IsNullOrEmpty(expectedSharedToken))
            return false;

        // Hash both to 32 bytes so FixedTimeEquals never leaks token length either!
        Span<byte> a = stackalloc byte[32];
        Span<byte> b = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(providedToken), a);
        SHA256.HashData(Encoding.UTF8.GetBytes(expectedSharedToken), b);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}

public sealed class AuthBruteForceGuard
{
    private sealed class Bucket
    {
        public int Count;
        public long WindowStartMs;
        public long BlockedUntilMs;
    }

    private readonly ConcurrentDictionary<string, Bucket> _loginBuckets = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Bucket> _registerBuckets = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeProvider _timeProvider;

    public AuthBruteForceGuard(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider;
    }

    public bool IsLoginBlocked(string ip, string username, out int retryAfterSeconds)
    {
        long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        string key = $"{ip}|{username}";
        if (_loginBuckets.TryGetValue(key, out Bucket? b))
        {
            lock (b)
            {
                if (b.BlockedUntilMs > nowMs)
                {
                    retryAfterSeconds = Math.Max(1, (int)((b.BlockedUntilMs - nowMs + 999) / 1000));
                    return true;
                }
            }
        }
        retryAfterSeconds = 0;
        return false;
    }

    public void RecordLoginFailure(string ip, string username)
    {
        if (_loginBuckets.Count > 10_000)
            PruneStale(_loginBuckets);

        long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        string key = $"{ip}|{username}";
        Bucket b = _loginBuckets.GetOrAdd(key, _ => new Bucket { WindowStartMs = nowMs });
        lock (b)
        {
            if (nowMs - b.WindowStartMs > 300_000)
            {
                b.WindowStartMs = nowMs;
                b.Count = 0;
            }
            b.Count++;
            if (b.Count >= 8)
                b.BlockedUntilMs = nowMs + 180_000; // 3-minute cooldown
        }
    }

    public void RecordLoginSuccess(string ip, string username)
    {
        _loginBuckets.TryRemove($"{ip}|{username}", out _);
    }

    public bool CheckRegistrationAllowed(string ip, out int retryAfterSeconds)
    {
        if (_registerBuckets.Count > 10_000)
            PruneStale(_registerBuckets);

        long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        Bucket b = _registerBuckets.GetOrAdd(ip, _ => new Bucket { WindowStartMs = nowMs });
        lock (b)
        {
            if (b.BlockedUntilMs > nowMs)
            {
                retryAfterSeconds = Math.Max(1, (int)((b.BlockedUntilMs - nowMs + 999) / 1000));
                return false;
            }
            if (nowMs - b.WindowStartMs > 900_000)
            {
                b.WindowStartMs = nowMs;
                b.Count = 0;
            }
            b.Count++;
            if (b.Count > 10)
            {
                b.BlockedUntilMs = nowMs + 900_000; // 15-minute cooldown per CLIENT_AUTH_HANDOFF.md
                retryAfterSeconds = 900;
                return false;
            }
        }
        retryAfterSeconds = 0;
        return true;
    }

    private void PruneStale(ConcurrentDictionary<string, Bucket> dict)
    {
        long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        foreach (var kvp in dict)
        {
            if (nowMs - kvp.Value.WindowStartMs > 900_000 && kvp.Value.BlockedUntilMs <= nowMs)
                dict.TryRemove(kvp.Key, out _);
        }
    }
}
