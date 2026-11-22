using System.Globalization;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Crypto;
using DigitalConnectPlus.Server.Data;
using DigitalConnectPlus.Server.Models;
using DigitalConnectPlus.Server.Security;
using DigitalConnectPlus.Server.Services;
using DigitalConnectPlus.Server.Tls;

namespace DigitalConnectPlus.Server.Endpoints;

public static class RelayEndpoints
{
    private const string PhoneSignatureHeader = "X-Gen5W-Phone-Signature";

    public static void MapGen5WRelayEndpoints(this IEndpointRouteBuilder app)
    {
        // Let's Encrypt HTTP-01 ACME Challenge Endpoint
        app.MapGet("/.well-known/acme-challenge/{token}", (string token, AcmeChallengeStore store) =>
        {
            if (store.TryGetKeyAuthorization(token, out string keyAuth))
                return Results.Text(keyAuth, "text/plain; charset=utf-8");
            return Results.NotFound();
        });

        // 1. Public Health Check (no Bearer token required)
        IResult HandleHealth(TimeProvider timeProvider) =>
            Results.Ok(new HealthResponse
            {
                Ok = true,
                Service = ServerConstants.HealthServiceId,
                Version = ServerConstants.Version,
                TimeMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds()
            });

        app.MapGet("/api/v1/health", HandleHealth);
        app.MapGet("/health", HandleHealth);

        // 2. Car Registration & Paired Phone Trust Sync
        app.MapPost("/api/v1/cars/register", HandleCarRegisterAsync);

        // 3. Phone Command Submission
        app.MapPost("/api/v1/commands", HandleSubmitCommandAsync);

        // 4. Phone Status Poll & Encrypted Telemetry Fetch
        app.MapGet("/api/v1/commands", HandleGetPhoneCommandsAsync);

        // 5. Phone Instant Atomic Command Cancellation
        app.MapDelete("/api/v1/commands/{commandId}", HandleCancelCommandAsync);

        // 6. Car Opportunistic Long-Poll + Encrypted Telemetry Upload
        app.MapPost("/api/v1/car/poll", HandleCarPollAsync);

        // 7. Car Execution Receipt (Ack)
        app.MapPost("/api/v1/car/ack", HandleCarAckAsync);
    }

    private static async Task<IResult> HandleCarRegisterAsync(
        CarRegisterRequest? req,
        HttpContext http,
        OperatorAccessValidator accessValidator,
        RelayDatabase db,
        RateLimitService rateLimiter,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var (allowed, err, principal) = await accessValidator.AuthenticateRequestAsync(http, ct);
        if (!allowed) return err!;

        if (req == null || !Gen5WCrypto.IsValidCarId(req.CarId))
            return BadRequest("Invalid or missing carId.");

        if (!rateLimiter.TryAcquireCar(req.CarId))
            return TooManyRequests("Per-car rate limit exceeded.");

        if (!Gen5WCrypto.TryDeriveKeyFingerprintHex(req.CarPublicKey, out string carFp))
            return BadRequest("Invalid carPublicKey: expected Base64 NIST P-256 SPKI DER.");

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        if (!Gen5WCrypto.IsWithinClockSkew(req.TimestampMs, nowMs))
            return Unauthorized("Clock skew exceeded (±90s) on timestampMs.");

        // Signature #1: "GEN5W-CAR-REG-V1|" + carId + "|" + deriveKeyFingerprintHex(carPublicKey) + "|" + timestampMs
        string regCanonical = Gen5WCrypto.BuildCarRegisterCanonical(req.CarId, carFp, req.TimestampMs);
        if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(req.CarPublicKey, regCanonical, req.CarSignature))
            return Unauthorized("Invalid carSignature on car registration.");

        List<AuthorizedPhoneDto> incomingPhones = req.AuthorizedPhones ?? [];
        if (incomingPhones.Count > 64)
            return BadRequest("authorizedPhones exceeds maximum limit (64).");

        var verifiedPhones = new List<AuthorizedPhoneRecord>(incomingPhones.Count);
        var seenPhoneIds = new HashSet<string>(StringComparer.Ordinal);

        foreach (AuthorizedPhoneDto p in incomingPhones)
        {
            if (!Gen5WCrypto.IsValidPhoneId(p.PhoneId))
                return BadRequest($"Invalid phoneId '{p.PhoneId}'.");

            if (!seenPhoneIds.Add(p.PhoneId))
                return BadRequest($"Duplicate phoneId '{p.PhoneId}' in authorizedPhones.");

            if (p.PairedAtMs <= 0)
                return BadRequest($"Invalid pairedAtMs for '{p.PhoneId}'.");

            if ((p.PhoneName?.Length ?? 0) > 128 || (p.Platform?.Length ?? 0) > 32)
                return BadRequest("phoneName or platform exceeds maximum length.");

            if (!Gen5WCrypto.TryDeriveKeyFingerprintHex(p.PhonePublicKey, out string phoneFp))
                return BadRequest($"Invalid phonePublicKey for '{p.PhoneId}'.");

            // Signature #2: "GEN5W-GRANT-V1|" + carId + "|" + phoneId + "|" + deriveKeyFingerprintHex(phonePublicKey) + "|" + pairedAtMs
            string grantCanonical = Gen5WCrypto.BuildPairingGrantCanonical(req.CarId, p.PhoneId, phoneFp, p.PairedAtMs);
            if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(req.CarPublicKey, grantCanonical, p.CarGrantSignature))
                return Forbidden($"Invalid carGrantSignature for phone '{p.PhoneId}'.");

            verifiedPhones.Add(new AuthorizedPhoneRecord(
                CarId: req.CarId,
                PhoneId: p.PhoneId,
                PhoneName: p.PhoneName,
                Platform: p.Platform,
                PhonePublicKey: p.PhonePublicKey,
                KeyFingerprint: phoneFp,
                PairedAtMs: p.PairedAtMs,
                CarGrantSignature: p.CarGrantSignature));
        }

        CarRegisterResultStatus status = await db.RegisterOrUpdateCarAsync(
            req.CarId,
            req.CarPublicKey,
            carFp,
            req.TimestampMs,
            nowMs,
            verifiedPhones,
            principal,
            ct);

        switch (status)
        {
            case CarRegisterResultStatus.TofuKeyMismatch:
                metrics.LogEvent("SEC", $"Blocked TOFU public-key mismatch attempt on {ShortId(req.CarId)}.");
                return Forbidden("Car public key mismatch (TOFU pinning violation).");

            case CarRegisterResultStatus.AccountForbidden:
                return Forbidden("This carId is already bound to a different account.");

            case CarRegisterResultStatus.AccountCarQuotaExceeded:
                return Forbidden("Account maximum car quota reached.");

            case CarRegisterResultStatus.StaleTimestampReplay:
                return Unauthorized("Stale registration timestamp (older than last registered sync).");

            default:
                metrics.LogEvent("CAR", $"Synced {ShortId(req.CarId)} ({verifiedPhones.Count} paired phone(s)).");
                return Results.Ok(new CarRegisterResponse
                {
                    Ok = true,
                    CarId = req.CarId,
                    AuthorizedPhoneCount = verifiedPhones.Count
                });
        }
    }

    private static async Task<IResult> HandleSubmitCommandAsync(
        CommandEnvelopeDto? req,
        HttpContext http,
        OperatorAccessValidator accessValidator,
        SettingsManager settings,
        RelayDatabase db,
        CarPollNotifier notifier,
        RateLimitService rateLimiter,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var (allowed, err, principal) = await accessValidator.AuthenticateRequestAsync(http, ct);
        if (!allowed) return err!;

        if (req == null)
            return BadRequest("Missing JSON command envelope.");

        if (!Gen5WCrypto.IsValidCommandId(req.CommandId))
            return BadRequest("Invalid commandId format.");
        if (!Gen5WCrypto.IsValidCarId(req.CarId))
            return BadRequest("Invalid carId format.");
        if (!Gen5WCrypto.IsValidPhoneId(req.PhoneId))
            return BadRequest("Invalid phoneId format.");

        if (!rateLimiter.TryAcquireCar(req.CarId))
            return TooManyRequests("Per-car rate limit exceeded.");

        if ((req.ClientHint?.Length ?? 0) > 512)
            return BadRequest("clientHint exceeds maximum length (512).");

        if (!ValidateE2eeBox(req.E2ee, out string? boxErr))
            return BadRequest(boxErr!);

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        if (!Gen5WCrypto.IsWithinClockSkew(req.IssuedAtMs, nowMs))
            return Unauthorized("Clock skew exceeded (±90s) on issuedAtMs.");

        long ttlMs = req.ExpiresAtMs - req.IssuedAtMs;
        if (ttlMs <= 0 || ttlMs > ServerConstants.MaxCommandTtlMs)
            return BadRequest("Invalid command expiration window: expected 0 < (expiresAtMs - issuedAtMs) <= 305000.");

        CarRecord? car = await db.GetCarAsync(req.CarId, ct);
        if (car == null)
            return NotFound("Car has not connected to this relay server yet");

        if (principal != null && car.OwnerKeyId != principal.OwnerKeyId)
            return Forbidden("Car belongs to a different account.");

        // Authorize phoneId via registered authorizedPhones OR Car-signed PairingGrant proof
        AuthorizedPhoneRecord? authorizedPhone = await db.GetAuthorizedPhoneAsync(req.CarId, req.PhoneId, ct);
        if (authorizedPhone != null)
        {
            if (req.PairingProof != null)
            {
                if (!Gen5WCrypto.TryDeriveKeyFingerprintHex(req.PairingProof.PhonePublicKey, out string proofFp) ||
                    !string.Equals(proofFp, authorizedPhone.KeyFingerprint, StringComparison.Ordinal))
                {
                    return Forbidden("pairingProof phonePublicKey does not match registered phone key.");
                }

                string grantCanonical = Gen5WCrypto.BuildPairingGrantCanonical(
                    req.CarId, req.PhoneId, proofFp, req.PairingProof.PairedAtMs);
                if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(car.CarPublicKey, grantCanonical, req.PairingProof.CarGrantSignature))
                    return Forbidden("Invalid carGrantSignature in pairingProof.");
            }
        }
        else
        {
            if (req.PairingProof == null)
                return Forbidden("Phone is not authorized for this car (missing pairingProof).");

            if (req.PairingProof.PairedAtMs <= 0 ||
                !Gen5WCrypto.TryDeriveKeyFingerprintHex(req.PairingProof.PhonePublicKey, out string proofFp))
            {
                return BadRequest("Invalid pairingProof key or pairedAtMs.");
            }

            string grantCanonical = Gen5WCrypto.BuildPairingGrantCanonical(
                req.CarId, req.PhoneId, proofFp, req.PairingProof.PairedAtMs);
            if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(car.CarPublicKey, grantCanonical, req.PairingProof.CarGrantSignature))
                return Forbidden("Invalid carGrantSignature in pairingProof.");

            authorizedPhone = await db.TryEnrollPhoneViaPairingProofAsync(
                car,
                req.PhoneId,
                req.PairingProof.PhonePublicKey,
                proofFp,
                req.PairingProof.PairedAtMs,
                req.PairingProof.CarGrantSignature,
                ct);

            if (authorizedPhone == null)
                return Forbidden("Pairing grant has been revoked or superseded by a newer car sync.");
        }

        // Signature #3: "GEN5W-ENV-V1|" + commandId + "|" + carId + "|" + phoneId + "|" + issuedAtMs + "|" + expiresAtMs + "|" + boxDigestHex
        string boxDigestHex = Gen5WCrypto.ComputeBoxDigestHex(
            req.E2ee!.EphemeralPubKey, req.E2ee.Iv, req.E2ee.Ciphertext, req.E2ee.Mac);

        string envCanonical = Gen5WCrypto.BuildCommandEnvelopeCanonical(
            req.CommandId, req.CarId, req.PhoneId, req.IssuedAtMs, req.ExpiresAtMs, boxDigestHex);

        if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(authorizedPhone.PhonePublicKey, envCanonical, req.PhoneSignature))
            return Unauthorized("Invalid phoneSignature on command envelope.");

        EnqueueCommandStatus enqueueResult = await db.EnqueueCommandAsync(
            req,
            nowMs,
            settings.Current.MaxQueuedCommandsPerCar,
            ct);

        if (enqueueResult == EnqueueCommandStatus.DuplicateCommandId)
            return Conflict("Duplicate commandId.");

        if (enqueueResult == EnqueueCommandStatus.QueueLimitReached)
            return TooManyRequests("Maximum active queued commands reached for this car.");

        // Immediately wake any active long-polling car connection!
        notifier.NotifyCommandQueued(req.CarId);
        metrics.LogEvent("CMD", $"Queued {ShortId(req.CommandId)} for {ShortId(req.CarId)}.");

        return Results.Ok(new CommandSubmitResponse
        {
            Ok = true,
            CommandId = req.CommandId,
            Status = CommandStatuses.Queued,
            ExpiresAtMs = req.ExpiresAtMs
        });
    }

    private static async Task<IResult> HandleGetPhoneCommandsAsync(
        HttpContext http,
        OperatorAccessValidator accessValidator,
        RelayDatabase db,
        RateLimitService rateLimiter,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var (allowed, err, principal) = await accessValidator.AuthenticateRequestAsync(http, ct);
        if (!allowed) return err!;

        string? carId = http.Request.Query["carId"].FirstOrDefault();
        string? phoneId = http.Request.Query["phoneId"].FirstOrDefault();
        string? tsRaw = http.Request.Query["ts"].FirstOrDefault();
        string? sig = http.Request.Headers[PhoneSignatureHeader].FirstOrDefault();

        if (!Gen5WCrypto.IsValidCarId(carId) || !Gen5WCrypto.IsValidPhoneId(phoneId))
            return BadRequest("Invalid or missing carId / phoneId query parameter.");

        if (!long.TryParse(tsRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out long ts))
            return BadRequest("Invalid or missing ts query parameter.");

        if (string.IsNullOrWhiteSpace(sig))
            return Unauthorized($"Missing {PhoneSignatureHeader} header.");

        if (!rateLimiter.TryAcquireCar(carId!))
            return TooManyRequests("Per-car rate limit exceeded.");

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        if (!Gen5WCrypto.IsWithinClockSkew(ts, nowMs))
            return Unauthorized("Clock skew exceeded (±90s) on ts.");

        CarRecord? car = await db.GetCarAsync(carId!, ct);
        if (car == null)
            return NotFound("Car has not connected to this relay server yet");

        if (principal != null && car.OwnerKeyId != principal.OwnerKeyId)
            return Forbidden("Car belongs to a different account.");

        AuthorizedPhoneRecord? authPhone = await db.GetAuthorizedPhoneAsync(carId!, phoneId!, ct);
        if (authPhone == null)
            return Forbidden("Phone is not authorized for this car.");

        // Signature #4: "GEN5W-STATUS-V1|" + carId + "|" + phoneId + "|" + ts
        string canonical = Gen5WCrypto.BuildPhoneStatusCanonical(carId!, phoneId!, ts);
        if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(authPhone.PhonePublicKey, canonical, sig))
            return Unauthorized("Invalid X-Gen5W-Phone-Signature.");

        var (commands, telemetry) = await db.GetPhoneCommandsAndTelemetryAsync(carId!, phoneId!, nowMs, ct);

        return Results.Ok(new PhoneCommandsStatusResponse
        {
            Ok = true,
            Commands = commands,
            EncryptedTelemetry = telemetry
        });
    }

    private static async Task<IResult> HandleCancelCommandAsync(
        string commandId,
        HttpContext http,
        OperatorAccessValidator accessValidator,
        RelayDatabase db,
        RateLimitService rateLimiter,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var (allowed, err, principal) = await accessValidator.AuthenticateRequestAsync(http, ct);
        if (!allowed) return err!;

        string? carId = http.Request.Query["carId"].FirstOrDefault();
        string? phoneId = http.Request.Query["phoneId"].FirstOrDefault();
        string? tsRaw = http.Request.Query["ts"].FirstOrDefault();
        string? sig = http.Request.Headers[PhoneSignatureHeader].FirstOrDefault();

        if (!Gen5WCrypto.IsValidCommandId(commandId))
            return BadRequest("Invalid commandId.");
        if (!Gen5WCrypto.IsValidCarId(carId) || !Gen5WCrypto.IsValidPhoneId(phoneId))
            return BadRequest("Invalid or missing carId / phoneId query parameter.");
        if (!long.TryParse(tsRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out long ts))
            return BadRequest("Invalid or missing ts query parameter.");
        if (string.IsNullOrWhiteSpace(sig))
            return Unauthorized($"Missing {PhoneSignatureHeader} header.");

        if (!rateLimiter.TryAcquireCar(carId!))
            return TooManyRequests("Per-car rate limit exceeded.");

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        if (!Gen5WCrypto.IsWithinClockSkew(ts, nowMs))
            return Unauthorized("Clock skew exceeded (±90s) on ts.");

        CarRecord? car = await db.GetCarAsync(carId!, ct);
        if (car == null)
            return NotFound("Car has not connected to this relay server yet");

        if (principal != null && car.OwnerKeyId != principal.OwnerKeyId)
            return Forbidden("Car belongs to a different account.");

        AuthorizedPhoneRecord? authPhone = await db.GetAuthorizedPhoneAsync(carId!, phoneId!, ct);
        if (authPhone == null)
            return Forbidden("Phone is not authorized for this car.");

        // Signature #5: "GEN5W-CANCEL-V1|" + commandId + "|" + carId + "|" + phoneId + "|" + ts
        string canonical = Gen5WCrypto.BuildPhoneCancelCanonical(commandId, carId!, phoneId!, ts);
        if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(authPhone.PhonePublicKey, canonical, sig))
            return Unauthorized("Invalid X-Gen5W-Phone-Signature.");

        var (outcome, existingStatus) = await db.CancelCommandAtomicallyAsync(commandId, carId!, nowMs, ct);
        return outcome switch
        {
            CancelCommandOutcome.NotFound => NotFound("Command not found."),
            CancelCommandOutcome.AlreadyTerminal => Conflict($"Command already {existingStatus}"),
            _ => LogCancelAndReturnOk(metrics, commandId, carId!)
        };
    }

    private static IResult LogCancelAndReturnOk(MetricsTracker metrics, string commandId, string carId)
    {
        metrics.LogEvent("CMD", $"Canceled {ShortId(commandId)} for {ShortId(carId)}.");
        return Results.Ok(new CommandCancelResponse
        {
            Ok = true,
            CommandId = commandId,
            Status = CommandStatuses.Canceled
        });
    }

    private static async Task<IResult> HandleCarPollAsync(
        CarPollRequest? req,
        HttpContext http,
        OperatorAccessValidator accessValidator,
        RelayDatabase db,
        CarPollNotifier notifier,
        RateLimitService rateLimiter,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var (allowed, err, principal) = await accessValidator.AuthenticateRequestAsync(http, ct);
        if (!allowed) return err!;

        if (req == null || !Gen5WCrypto.IsValidCarId(req.CarId))
            return BadRequest("Invalid or missing carId.");

        if (!Gen5WCrypto.IsValidNonce(req.Nonce))
            return BadRequest("Invalid or missing nonce.");

        if (!rateLimiter.TryAcquireCar(req.CarId))
            return TooManyRequests("Per-car rate limit exceeded.");

        // Exact 404 CAR_NOT_REGISTERED error code triggers automatic /api/v1/cars/register on the car head unit!
        CarRecord? car = await db.GetCarAsync(req.CarId, ct);
        if (car == null)
            return NotFound("CAR_NOT_REGISTERED");

        if (principal != null && car.OwnerKeyId != principal.OwnerKeyId)
            return Forbidden("Car belongs to a different account.");

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        if (!Gen5WCrypto.IsWithinClockSkew(req.TimestampMs, nowMs))
            return Unauthorized("Clock skew exceeded (±90s) on timestampMs.");

        // Signature #6: "GEN5W-POLL-V1|" + carId + "|" + timestampMs + "|" + nonce
        string canonical = Gen5WCrypto.BuildCarPollCanonical(req.CarId, req.TimestampMs, req.Nonce);
        if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(car.CarPublicKey, canonical, req.CarSignature))
            return Unauthorized("Invalid carSignature on poll request.");

        // Validate optional encryptedTelemetry map before touching DB
        Dictionary<string, EncryptedTelemetryDto>? validatedTelemetry = null;
        if (req.EncryptedTelemetry is { Count: > 0 })
        {
            if (req.EncryptedTelemetry.Count > 32)
                return BadRequest("encryptedTelemetry map exceeds maximum phone entries (32).");

            validatedTelemetry = new Dictionary<string, EncryptedTelemetryDto>(req.EncryptedTelemetry.Count, StringComparer.Ordinal);
            foreach (var (phoneId, tel) in req.EncryptedTelemetry)
            {
                if (!Gen5WCrypto.IsValidPhoneId(phoneId))
                    return BadRequest($"Invalid phoneId '{phoneId}' in encryptedTelemetry.");

                if (tel == null ||
                    !Gen5WCrypto.IsValidP256SpkiBase64(tel.EphemeralPubKey) ||
                    !Gen5WCrypto.IsValidStrictBase64(tel.Iv, 12, 32) ||
                    !Gen5WCrypto.IsValidStrictBase64(tel.Mac, 16, 64) ||
                    !Gen5WCrypto.IsValidStrictBase64(tel.Ciphertext, 1, 131_072))
                {
                    return BadRequest($"Malformed encryptedTelemetry box for '{phoneId}'.");
                }

                validatedTelemetry[phoneId] = tel;
            }
        }

        // Consume replay nonce & persist telemetry atomically
        bool nonceAccepted = await db.TryConsumePollNonceAndSaveTelemetryAsync(req.CarId, req.Nonce, nowMs, validatedTelemetry, ct);
        if (!nonceAccepted)
            return Unauthorized("Replay detected: poll nonce already used within 5-minute window.");

        int waitSec = Math.Clamp(
            req.WaitSeconds ?? ServerConstants.DefaultLongPollWaitSeconds,
            0,
            ServerConstants.MaxLongPollWaitSeconds);

        DateTimeOffset deadline = DateTimeOffset.UtcNow.AddSeconds(waitSec);

        while (true)
        {
            long genBefore = notifier.GetGeneration(req.CarId);
            long checkNowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
            List<CommandEnvelopeDto> ready = await db.FetchQueuedCommandsForCarAsync(req.CarId, checkNowMs, ct);

            if (ready.Count > 0 || waitSec == 0)
            {
                return Results.Ok(new CarPollResponse
                {
                    Ok = true,
                    Commands = ready
                });
            }

            TimeSpan remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.FromMilliseconds(15))
            {
                return Results.Ok(new CarPollResponse
                {
                    Ok = true,
                    Commands = []
                });
            }

            bool woken = await notifier.WaitForNextGenerationAsync(req.CarId, genBefore, remaining, ct);
            if (!woken)
            {
                long finalNowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
                List<CommandEnvelopeDto> finalCheck = await db.FetchQueuedCommandsForCarAsync(req.CarId, finalNowMs, ct);
                return Results.Ok(new CarPollResponse
                {
                    Ok = true,
                    Commands = finalCheck
                });
            }
        }
    }

    private static async Task<IResult> HandleCarAckAsync(
        CarAckRequest? req,
        HttpContext http,
        OperatorAccessValidator accessValidator,
        RelayDatabase db,
        RateLimitService rateLimiter,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        CancellationToken ct)
    {
        var (allowed, err, principal) = await accessValidator.AuthenticateRequestAsync(http, ct);
        if (!allowed) return err!;

        if (req == null || !Gen5WCrypto.IsValidCommandId(req.CommandId) || !Gen5WCrypto.IsValidCarId(req.CarId))
            return BadRequest("Invalid commandId or carId.");

        if (!rateLimiter.TryAcquireCar(req.CarId))
            return TooManyRequests("Per-car rate limit exceeded.");

        string msg = req.Message ?? "";
        if (msg.Length > 512)
            return BadRequest("message exceeds maximum length (512).");

        CarRecord? car = await db.GetCarAsync(req.CarId, ct);
        if (car == null)
            return NotFound("CAR_NOT_REGISTERED");

        if (principal != null && car.OwnerKeyId != principal.OwnerKeyId)
            return Forbidden("Car belongs to a different account.");

        long nowMs = timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        if (!Gen5WCrypto.IsWithinClockSkew(req.ExecutedAtMs, nowMs))
            return Unauthorized("Clock skew exceeded (±90s) on executedAtMs.");

        // Signature #7: "GEN5W-ACK-V1|" + commandId + "|" + carId + "|" + (ok ? "1" : "0") + "|" + executedAtMs + "|" + sha256HexUtf8(message)
        string canonical = Gen5WCrypto.BuildCarAckCanonical(req.CommandId, req.CarId, req.Ok, req.ExecutedAtMs, msg);
        if (!Gen5WCrypto.VerifyEcdsaP256DerBase64(car.CarPublicKey, canonical, req.CarSignature))
            return Unauthorized("Invalid carSignature on execution receipt.");

        bool updated = await db.AcknowledgeCommandAsync(req.CommandId, req.CarId, req.Ok, msg, req.ExecutedAtMs, nowMs, ct);
        if (!updated)
            return NotFound("Command not found for this car.");

        string finalStatus = req.Ok ? CommandStatuses.Executed : CommandStatuses.Failed;
        metrics.LogEvent("ACK", $"{ShortId(req.CommandId)} -> {finalStatus}.");

        return Results.Ok(new CarAckResponse
        {
            Ok = true,
            CommandId = req.CommandId,
            Status = finalStatus
        });
    }

    private static bool ValidateE2eeBox(E2eeBoxDto? box, out string? error)
    {
        if (box == null)
        {
            error = "Missing e2ee payload.";
            return false;
        }
        if (!Gen5WCrypto.IsValidP256SpkiBase64(box.EphemeralPubKey))
        {
            error = "Invalid e2ee.ephemeralPubKey: expected Base64 P-256 SPKI DER.";
            return false;
        }
        if (!Gen5WCrypto.IsValidStrictBase64(box.Iv, 12, 32))
        {
            error = "Invalid e2ee.iv Base64.";
            return false;
        }
        if (!Gen5WCrypto.IsValidStrictBase64(box.Mac, 16, 64))
        {
            error = "Invalid e2ee.mac Base64.";
            return false;
        }
        if (!Gen5WCrypto.IsValidStrictBase64(box.Ciphertext, 1, 196_608))
        {
            error = "Invalid e2ee.ciphertext Base64.";
            return false;
        }
        error = null;
        return true;
    }

    private static string ShortId(string id) =>
        id.Length <= 14 ? id : id[..14] + "…";

    private static IResult BadRequest(string error) =>
        Results.Json(new ApiErrorResponse { Error = error }, statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unauthorized(string error) =>
        Results.Json(new ApiErrorResponse { Error = error }, statusCode: StatusCodes.Status401Unauthorized);

    private static IResult Forbidden(string error) =>
        Results.Json(new ApiErrorResponse { Error = error }, statusCode: StatusCodes.Status403Forbidden);

    private static IResult NotFound(string error) =>
        Results.Json(new ApiErrorResponse { Error = error }, statusCode: StatusCodes.Status404NotFound);

    private static IResult Conflict(string error) =>
        Results.Json(new ApiErrorResponse { Error = error }, statusCode: StatusCodes.Status409Conflict);

    private static IResult TooManyRequests(string error) =>
        Results.Json(new ApiErrorResponse { Error = error }, statusCode: StatusCodes.Status429TooManyRequests);
}
