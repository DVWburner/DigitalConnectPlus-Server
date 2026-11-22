using System.Globalization;
using System.Text.RegularExpressions;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Data;
using DigitalConnectPlus.Server.Models;
using DigitalConnectPlus.Server.Security;
using DigitalConnectPlus.Server.Services;

namespace DigitalConnectPlus.Server.Endpoints;

public sealed class OperatorAccessValidator
{
    private readonly SettingsManager _settings;
    private readonly RelayDatabase _db;
    private readonly AccountTokenService _tokenService;
    private readonly TimeProvider _timeProvider;

    public OperatorAccessValidator(
        SettingsManager settings,
        RelayDatabase db,
        AccountTokenService tokenService,
        TimeProvider timeProvider)
    {
        _settings = settings;
        _db = db;
        _tokenService = tokenService;
        _timeProvider = timeProvider;
    }

    public async Task<(bool Allowed, IResult? ErrorResult, AuthenticatedPrincipalInfo? Principal)> AuthenticateRequestAsync(
        HttpContext http,
        CancellationToken ct)
    {
        ServerSettings s = _settings.Current;
        NormalizedAuthMode mode = s.NormalizedAuth;

        if (mode == NormalizedAuthMode.OpenDevicePopOnly)
            return (true, null, null);

        string? bearer = ExtractBearerToken(http.Request.Headers.Authorization.FirstOrDefault());
        if (string.IsNullOrEmpty(bearer))
        {
            return (false, Results.Json(
                new ApiErrorResponse { Error = "Authorization: Bearer <token> header is required." },
                statusCode: StatusCodes.Status401Unauthorized), null);
        }

        if (mode == NormalizedAuthMode.SharedToken)
        {
            if (!AccountTokenService.FixedTimeVerifySharedToken(bearer, s.ServerSharedToken))
            {
                return (false, Results.Json(
                    new ApiErrorResponse { Error = "Invalid server Bearer token." },
                    statusCode: StatusCodes.Status401Unauthorized), null);
            }

            return (true, null, null);
        }

        // NormalizedAuthMode.AccountsPlusDevicePop ("accounts" / "account_plus_device_pop")
        long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();

        if (bearer.StartsWith("dcp_", StringComparison.Ordinal))
        {
            ApiTokenRecord? tok = await _db.ValidateAndTouchApiTokenAsync(bearer, nowMs, ct);
            if (tok == null)
            {
                return (false, Results.Json(
                    new ApiErrorResponse { Error = "Invalid or revoked API token." },
                    statusCode: StatusCodes.Status401Unauthorized), null);
            }

            if (tok.AccountId.HasValue)
            {
                AccountRecord? acct = await _db.GetAccountByIdAsync(tok.AccountId.Value, ct);
                if (acct == null || acct.IsDisabled)
                {
                    return (false, Results.Json(
                        new ApiErrorResponse { Error = "Account disabled or not found." },
                        statusCode: StatusCodes.Status401Unauthorized), null);
                }
                return (true, null, new AuthenticatedPrincipalInfo(acct.Id, acct.Username, acct.MaxCars));
            }

            return (true, null, new AuthenticatedPrincipalInfo(-tok.Id, tok.Label, tok.MaxCars));
        }

        if (_tokenService.TryValidateAccountJwt(bearer, out int accountId, out int tokenVersion))
        {
            AccountRecord? acct = await _db.GetAccountByIdAsync(accountId, ct);
            if (acct != null && !acct.IsDisabled && acct.TokenVersion == tokenVersion)
            {
                return (true, null, new AuthenticatedPrincipalInfo(acct.Id, acct.Username, acct.MaxCars));
            }
        }

        return (false, Results.Json(
            new ApiErrorResponse { Error = "Invalid or expired Bearer token." },
            statusCode: StatusCodes.Status401Unauthorized), null);
    }

    public static string? ExtractBearerToken(string? authHeader)
    {
        if (string.IsNullOrWhiteSpace(authHeader))
            return null;

        const string prefix = "Bearer ";
        if (!authHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return null;

        string token = authHeader[prefix.Length..].Trim();
        return token.Length is > 0 and <= 2048 ? token : null;
    }
}

public static partial class AuthEndpoints
{
    [GeneratedRegex("^[a-zA-Z0-9_-]{3,32}$", RegexOptions.CultureInvariant)]
    private static partial Regex UsernameRegex();

    public static void MapAccountAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/auth");
        group.MapPost("/register", RegisterAsync);
        group.MapPost("/login", LoginAsync);
        group.MapGet("/me", GetMeAsync);
    }

    private static async Task<IResult> RegisterAsync(
        AccountCredentialsRequest? req,
        HttpContext http,
        SettingsManager settings,
        RelayDatabase db,
        AccountTokenService tokenService,
        AuthBruteForceGuard guard,
        RateLimitService rateLimiter,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        ServerSettings s = settings.Current;
        if (!s.AllowPublicAccountRegistration)
        {
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Public account registration is disabled on this server." },
                statusCode: StatusCodes.Status403Forbidden);
        }

        string clientIp = rateLimiter.ResolveClientIp(http);
        if (!guard.CheckRegistrationAllowed(clientIp, out int retryAfter))
        {
            http.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
            return Results.Json(
                new AuthActionResponse
                {
                    Ok = false,
                    Error = "Account registration is temporarily disabled due to high signup volume. Please try again later."
                },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        string username = (req?.Username ?? "").Trim();
        string password = req?.Password ?? "";

        if (!UsernameRegex().IsMatch(username))
        {
            return Results.BadRequest(new AuthActionResponse
            {
                Ok = false,
                Error = "Username must be 3 to 32 characters and contain only letters, numbers, '-' or '_'."
            });
        }

        if (password.IndexOf('\0') >= 0 || password.Length < 8 || password.Length > 128)
        {
            return Results.BadRequest(new AuthActionResponse
            {
                Ok = false,
                Error = "Password must be between 8 and 128 characters."
            });
        }

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        var (hash, salt, iterations) = PasswordHasher.HashPassword(password);
        var (created, account) = await db.CreateAccountAsync(
            username, hash, salt, iterations, Math.Max(1, s.MaxCarsPerAccount), nowMs, ct);

        if (!created || account == null)
        {
            return Results.Conflict(new AuthActionResponse
            {
                Ok = false,
                Error = "That username is already taken."
            });
        }

        metrics.LogEvent("AUTH", $"Registered account #{account.Id}.");
        var (token, expiresAt) = tokenService.IssueAccountJwt(account);

        return Results.Json(
            new AuthActionResponse
            {
                Ok = true,
                Message = "Account created successfully.",
                Token = token,
                TokenType = "Bearer",
                ExpiresAt = expiresAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                Account = new AccountProfileDto
                {
                    Username = account.Username,
                    CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(account.CreatedAtMs).UtcDateTime
                        .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
                }
            },
            statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> LoginAsync(
        AccountCredentialsRequest? req,
        HttpContext http,
        RelayDatabase db,
        AccountTokenService tokenService,
        AuthBruteForceGuard guard,
        RateLimitService rateLimiter,
        CancellationToken ct)
    {
        string clientIp = rateLimiter.ResolveClientIp(http);
        string username = (req?.Username ?? "").Trim();
        string password = req?.Password ?? "";

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            return Results.BadRequest(new AuthActionResponse
            {
                Ok = false,
                Error = "Username and password are required."
            });
        }

        if (username.Length > 32 || password.Length > 128 || password.IndexOf('\0') >= 0)
        {
            guard.RecordLoginFailure(clientIp, username[..Math.Min(32, username.Length)]);
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Invalid username or password." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        if (guard.IsLoginBlocked(clientIp, username, out int retryAfter))
        {
            http.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
            return Results.Json(
                new AuthActionResponse
                {
                    Ok = false,
                    Error = "Too many failed sign-in attempts. Please wait a few minutes and try again."
                },
                statusCode: StatusCodes.Status429TooManyRequests);
        }

        AccountRecord? account = await db.GetAccountByUsernameAsync(username, ct);
        if (account == null)
        {
            // Constant-time dummy PBKDF2 to prevent username enumeration timing side-channels
            _ = PasswordHasher.VerifyPassword(password, PasswordHasher.DummyHash, PasswordHasher.DummySalt, PasswordHasher.DefaultIterations);
            guard.RecordLoginFailure(clientIp, username);
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Invalid username or password." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        if (account.IsDisabled || !PasswordHasher.VerifyPassword(password, account.PasswordHash, account.PasswordSalt, account.HashIterations))
        {
            guard.RecordLoginFailure(clientIp, username);
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Invalid username or password." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        guard.RecordLoginSuccess(clientIp, username);
        var (token, expiresAt) = tokenService.IssueAccountJwt(account);

        return Results.Ok(new AuthActionResponse
        {
            Ok = true,
            Message = "Signed in successfully.",
            Token = token,
            TokenType = "Bearer",
            ExpiresAt = expiresAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            Account = new AccountProfileDto
            {
                Username = account.Username,
                CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(account.CreatedAtMs).UtcDateTime
                    .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            }
        });
    }

    private static async Task<IResult> GetMeAsync(
        HttpContext http,
        RelayDatabase db,
        AccountTokenService tokenService,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        string? bearer = OperatorAccessValidator.ExtractBearerToken(http.Request.Headers.Authorization.FirstOrDefault());
        if (string.IsNullOrEmpty(bearer))
        {
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Authentication required." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        if (bearer.StartsWith("dcp_", StringComparison.Ordinal))
        {
            long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
            ApiTokenRecord? tok = await db.ValidateAndTouchApiTokenAsync(bearer, nowMs, ct);
            if (tok == null)
            {
                return Results.Json(
                    new AuthActionResponse { Ok = false, Error = "Invalid or revoked API token." },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new AuthActionResponse
            {
                Ok = true,
                Account = new AccountProfileDto
                {
                    Username = tok.Label,
                    CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(tok.CreatedAtMs).UtcDateTime
                        .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
                }
            });
        }

        if (!tokenService.TryValidateAccountJwt(bearer, out int accountId, out int tv))
        {
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Invalid or expired token." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        AccountRecord? account = await db.GetAccountByIdAsync(accountId, ct);
        if (account == null || account.IsDisabled || account.TokenVersion != tv)
        {
            return Results.Json(
                new AuthActionResponse { Ok = false, Error = "Account not found or disabled." },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return Results.Ok(new AuthActionResponse
        {
            Ok = true,
            Account = new AccountProfileDto
            {
                Username = account.Username,
                CreatedAt = DateTimeOffset.FromUnixTimeMilliseconds(account.CreatedAtMs).UtcDateTime
                    .ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)
            }
        });
    }
}
