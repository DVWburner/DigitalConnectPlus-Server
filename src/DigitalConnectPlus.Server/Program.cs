using System.Net;
using System.Text.Json;
using DigitalConnectPlus.Server.Cli;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Data;
using DigitalConnectPlus.Server.Endpoints;
using DigitalConnectPlus.Server.Ipc;
using DigitalConnectPlus.Server.Models;
using DigitalConnectPlus.Server.Security;
using DigitalConnectPlus.Server.Services;
using DigitalConnectPlus.Server.Tls;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection.Extensions;

if (AdminCliHandler.IsCliCommand(args))
{
    int code = await AdminCliHandler.ExecuteAsync(args);
    Environment.Exit(code);
    return;
}

var builder = WebApplication.CreateBuilder(args);

// Enable Windows Service integration when started by Windows Service Control Manager (SCM)
builder.Host.UseWindowsService(options =>
{
    options.ServiceName = ServerConstants.WindowsServiceName;
});

var bootstrapSettingsManager = new SettingsManager();
ServerSettings initialSettings = bootstrapSettingsManager.Current;
bool isTestHost = string.Equals(
    Environment.GetEnvironmentVariable("DCP_TEST_HOST"),
    "1",
    StringComparison.Ordinal);

string listenerDescription = "TestServer";

if (!isTestHost)
{
    if (OperatingSystem.IsWindows() &&
        string.Equals(initialSettings.ListenerEngine, "HttpSys", StringComparison.OrdinalIgnoreCase))
    {
        string prefix = ResolveHttpSysUrlPrefix(initialSettings);
        listenerDescription = $"HTTP.sys ({prefix})";

        builder.WebHost.UseHttpSys(options =>
        {
            options.MaxRequestBodySize = initialSettings.MaxRequestBodyBytes;
            options.UrlPrefixes.Clear();
            options.UrlPrefixes.Add(prefix);
        });
    }
    else
    {
        builder.WebHost.ConfigureKestrel((context, kestrel) =>
        {
            SettingsManager sm = kestrel.ApplicationServices.GetRequiredService<SettingsManager>();
            CertificateProvider certProv = kestrel.ApplicationServices.GetRequiredService<CertificateProvider>();
            ServerSettings s = sm.Current;

            kestrel.AddServerHeader = false;
            kestrel.Limits.MaxRequestBodySize = s.MaxRequestBodyBytes;
            kestrel.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(65);
            kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);

            bool plainHttpOnly = string.Equals(s.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase);
            Action<Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions> configurePrimary = listenOpts =>
            {
                if (!plainHttpOnly)
                {
                    listenOpts.UseHttps((stream, clientHelloInfo, state, ct) =>
                        ValueTask.FromResult(certProv.GetSslServerOptions(clientHelloInfo.ServerName)), state: string.Empty);
                }
            };

            BindKestrelEndpoint(kestrel, s.ListenInterface, s.Port, configurePrimary);

            // Optional Port 80 HTTP-01 ACME Challenge responder for automatic Let's Encrypt issuance/renewal
            if (s.EnableHttpAcmeListener && s.HttpAcmePort != s.Port)
            {
                BindKestrelEndpoint(kestrel, s.ListenInterface, s.HttpAcmePort, _ => { });
            }
        });

        string proto = string.Equals(initialSettings.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase)
            ? "http"
            : "https";
        listenerDescription = $"Kestrel {proto}://{initialSettings.ListenInterface}:{initialSettings.Port}" +
            (initialSettings.EnableHttpAcmeListener ? $" (+ http://:{initialSettings.HttpAcmePort} ACME)" : "");
    }
}

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
});

// Core singletons (TryAddSingleton allows clean overrides in automated integration tests)
builder.Services.TryAddSingleton(TimeProvider.System);
builder.Services.TryAddSingleton(bootstrapSettingsManager);
builder.Services.TryAddSingleton(sp =>
{
    SettingsManager sm = sp.GetRequiredService<SettingsManager>();
    return new RelayDatabase(sm.ResolveDatabasePath());
});
builder.Services.TryAddSingleton<MetricsTracker>();
builder.Services.TryAddSingleton<CarPollNotifier>();
builder.Services.TryAddSingleton<RateLimitService>();
builder.Services.TryAddSingleton<AccountTokenService>();
builder.Services.TryAddSingleton<AuthBruteForceGuard>();
builder.Services.TryAddSingleton<OperatorAccessValidator>();
builder.Services.TryAddSingleton<CertificateProvider>();
builder.Services.TryAddSingleton<AcmeChallengeStore>();
builder.Services.TryAddSingleton<AcmeLetsEncryptService>();
builder.Services.TryAddSingleton<TrayIpcServer>();

builder.Services.AddHostedService<BackgroundMaintenanceService>();

if (!isTestHost)
{
    builder.Services.AddHostedService(sp => sp.GetRequiredService<AcmeLetsEncryptService>());
    builder.Services.AddHostedService(sp => sp.GetRequiredService<TrayIpcServer>());
}

var app = builder.Build();

// Initialize SQLite WAL schema, JWT signing secret, and TLS certificate state
{
    RelayDatabase db = app.Services.GetRequiredService<RelayDatabase>();
    byte[] jwtKey = await db.InitializeAsync();

    AccountTokenService tokenSvc = app.Services.GetRequiredService<AccountTokenService>();
    tokenSvc.InitializeSigningKey(jwtKey);

    CertificateProvider certProvider = app.Services.GetRequiredService<CertificateProvider>();
    certProvider.ReloadCertificate();

    TrayIpcServer ipc = app.Services.GetRequiredService<TrayIpcServer>();
    ipc.ActiveListenerDescription = listenerDescription;

    MetricsTracker metrics = app.Services.GetRequiredService<MetricsTracker>();
    metrics.LogEvent("BOOT", $"{ServerConstants.ProductName} v{ServerConstants.Version} online ({listenerDescription}).");
}

// Security headers, request size enforcement, rate limiting, and zero-redirect API protection
app.Use(async (context, next) =>
{
    MetricsTracker metrics = context.RequestServices.GetRequiredService<MetricsTracker>();
    SettingsManager sm = context.RequestServices.GetRequiredService<SettingsManager>();
    RateLimitService rateLimiter = context.RequestServices.GetRequiredService<RateLimitService>();
    ServerSettings s = sm.Current;

    metrics.RecordRequest();

    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Cache-Control"] = "no-store";

    // When Port 80 ACME listener is enabled alongside HTTPS, block API endpoints on plaintext Port 80
    // (Return 400 JSON rather than HTTP 301/308 redirect because Gen5W clients enforce followRedirects = false!)
    if (!isTestHost &&
        s.EnableHttpAcmeListener &&
        !string.Equals(s.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase) &&
        !context.Request.IsHttps &&
        context.Connection.LocalPort == s.HttpAcmePort)
    {
        PathString p = context.Request.Path;
        bool allowedOnHttp =
            p.StartsWithSegments("/.well-known/acme-challenge", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase) ||
            p.Equals("/health", StringComparison.OrdinalIgnoreCase);

        if (!allowedOnHttp)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(new ApiErrorResponse
            {
                Error = "HTTPS is required for all Gen5W Relay API endpoints."
            });
            return;
        }
    }

    // Optional Host header enforcement when CustomBindUrl specifies a hostname in Kestrel mode
    if (!string.IsNullOrWhiteSpace(s.CustomBindUrl) &&
        Uri.TryCreate(s.CustomBindUrl.Trim(), UriKind.Absolute, out Uri? customUri) &&
        !string.IsNullOrWhiteSpace(customUri.Host) &&
        customUri.Host is not "+" and not "*" and not "0.0.0.0")
    {
        string reqHost = context.Request.Host.Host;
        if (!string.IsNullOrEmpty(reqHost) && !string.Equals(reqHost, customUri.Host, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status421MisdirectedRequest;
            await context.Response.WriteAsJsonAsync(new ApiErrorResponse { Error = "Unrecognized Host header." });
            return;
        }
    }

    // Strict 256 KB body size limit
    int maxBytes = Math.Max(16_384, s.MaxRequestBodyBytes);
    if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodySizeFeature)
        bodySizeFeature.MaxRequestBodySize = maxBytes;

    if (context.Request.ContentLength is long len && len > maxBytes)
    {
        context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
        await context.Response.WriteAsJsonAsync(new ApiErrorResponse
        {
            Error = $"Request body exceeds maximum allowed size ({maxBytes} bytes)."
        });
        return;
    }

    // Per-IP sliding window rate limiting (skip health check & ACME challenge)
    if (!context.Request.Path.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase) &&
        !context.Request.Path.StartsWithSegments("/.well-known/acme-challenge", StringComparison.OrdinalIgnoreCase))
    {
        string clientIp = rateLimiter.ResolveClientIp(context);
        if (!rateLimiter.TryAcquireIp(clientIp))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            await context.Response.WriteAsJsonAsync(new ApiErrorResponse
            {
                Error = "Rate limit exceeded. Please slow down."
            });
            return;
        }
    }

    try
    {
        await next();
    }
    catch (BadHttpRequestException ex)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.Clear();
            context.Response.StatusCode = ex.StatusCode;
            string msg = ex.StatusCode == StatusCodes.Status413PayloadTooLarge
                ? $"Request body exceeds maximum allowed size ({maxBytes} bytes)."
                : "Malformed JSON request payload.";
            await context.Response.WriteAsJsonAsync(new ApiErrorResponse { Error = msg });
        }
    }
    catch (Exception ex)
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "Unhandled exception on {Method} {Path}", context.Request.Method, context.Request.Path);
        if (!context.Response.HasStarted)
        {
            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(new ApiErrorResponse
            {
                Error = "Internal server error."
            });
        }
    }
});

app.UseStatusCodePages(async statusCtx =>
{
    HttpResponse res = statusCtx.HttpContext.Response;
    if (res.HasStarted || res.ContentLength.HasValue || !string.IsNullOrEmpty(res.ContentType))
        return;

    string message = res.StatusCode switch
    {
        StatusCodes.Status404NotFound => "Endpoint not found.",
        StatusCodes.Status405MethodNotAllowed => "HTTP method not allowed.",
        StatusCodes.Status415UnsupportedMediaType => "Unsupported Content-Type; expected application/json.",
        _ => $"HTTP {res.StatusCode}"
    };
    await res.WriteAsJsonAsync(new ApiErrorResponse { Error = message });
});

app.MapGen5WRelayEndpoints();
app.MapAccountAuthEndpoints();

await app.RunAsync();

static void BindKestrelEndpoint(
    Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions kestrel,
    string? rawInterface,
    int port,
    Action<Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions> configure)
{
    string iface = (rawInterface ?? "0.0.0.0").Trim();
    if (iface is "" or "0.0.0.0" or "*")
    {
        kestrel.Listen(IPAddress.Any, port, configure);
    }
    else if (iface is "::" or "[::]" or "+")
    {
        kestrel.ListenAnyIP(port, configure);
    }
    else if (string.Equals(iface, "localhost", StringComparison.OrdinalIgnoreCase))
    {
        kestrel.ListenLocalhost(port, configure);
    }
    else if (IPAddress.TryParse(iface, out IPAddress? parsedIp))
    {
        kestrel.Listen(parsedIp, port, configure);
    }
    else
    {
        kestrel.Listen(IPAddress.Any, port, configure);
    }
}

static string ResolveHttpSysUrlPrefix(ServerSettings s)
{
    if (!string.IsNullOrWhiteSpace(s.CustomBindUrl))
    {
        string raw = s.CustomBindUrl.Trim();
        if (Uri.TryCreate(raw, UriKind.Absolute, out Uri? parsed) && parsed.IsDefaultPort)
        {
            return $"{parsed.Scheme}://{parsed.Host}:{s.Port}/";
        }
        return raw.EndsWith('/') ? raw : raw + "/";
    }

    string scheme = string.Equals(s.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase)
        ? "http"
        : "https";
    string? host = s.TryGetPublicHostname();
    string hostPart = !string.IsNullOrEmpty(host) ? host : "+";
    return $"{scheme}://{hostPart}:{s.Port}/";
}

public partial class Program { }
