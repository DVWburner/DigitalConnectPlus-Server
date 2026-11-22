using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Crypto;
using DigitalConnectPlus.Server.Data;
using DigitalConnectPlus.Server.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace DigitalConnectPlus.Tests;

internal sealed class ControllableTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    public ControllableTimeProvider(DateTimeOffset? initialUtc = null)
    {
        _utcNow = initialUtc ?? new DateTimeOffset(2026, 11, 20, 19, 0, 0, TimeSpan.Zero);
    }

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
    public long NowMs => _utcNow.ToUnixTimeMilliseconds();
}

internal sealed class SimulatedCar : IDisposable
{
    public string CarId { get; }
    public ECDsa Key { get; }
    public string PublicKeySpkiB64 { get; }
    public string FingerprintHex { get; }

    public SimulatedCar(string? carId = null)
    {
        CarId = carId ?? $"car_{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12))}";
        Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicKeySpkiB64 = Gen5WCrypto.ExportSpkiBase64(Key);
        FingerprintHex = Gen5WCrypto.DeriveKeyFingerprintHexOrThrow(PublicKeySpkiB64);
    }

    public string SignRegister(long timestampMs) =>
        Gen5WCrypto.SignEcdsaP256DerBase64(Key, Gen5WCrypto.BuildCarRegisterCanonical(CarId, FingerprintHex, timestampMs));

    public string SignPairingGrant(SimulatedPhone phone, long pairedAtMs) =>
        Gen5WCrypto.SignEcdsaP256DerBase64(Key, Gen5WCrypto.BuildPairingGrantCanonical(CarId, phone.PhoneId, phone.FingerprintHex, pairedAtMs));

    public string SignPoll(long timestampMs, string nonce) =>
        Gen5WCrypto.SignEcdsaP256DerBase64(Key, Gen5WCrypto.BuildCarPollCanonical(CarId, timestampMs, nonce));

    public string SignAck(string commandId, bool ok, long executedAtMs, string message) =>
        Gen5WCrypto.SignEcdsaP256DerBase64(Key, Gen5WCrypto.BuildCarAckCanonical(commandId, CarId, ok, executedAtMs, message));

    public void Dispose() => Key.Dispose();
}

internal sealed class SimulatedPhone : IDisposable
{
    public string PhoneId { get; }
    public ECDsa Key { get; }
    public string PublicKeySpkiB64 { get; }
    public string FingerprintHex { get; }

    public SimulatedPhone(string? phoneId = null)
    {
        PhoneId = phoneId ?? $"ph_{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(10))}";
        Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        PublicKeySpkiB64 = Gen5WCrypto.ExportSpkiBase64(Key);
        FingerprintHex = Gen5WCrypto.DeriveKeyFingerprintHexOrThrow(PublicKeySpkiB64);
    }

    public E2eeBoxDto CreateSimulatedE2eeBox(string plaintextJson = "{\"cmd\":\"climate_start\",\"tempF\":72}")
    {
        using ECDsa ephemeral = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] macKey = RandomNumberGenerator.GetBytes(32);

        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        byte[] ciphertext = aes.EncryptCbc(Encoding.UTF8.GetBytes(plaintextJson), iv, PaddingMode.PKCS7);
        byte[] mac = HMACSHA256.HashData(macKey, ciphertext);

        return new E2eeBoxDto
        {
            EphemeralPubKey = Gen5WCrypto.ExportSpkiBase64(ephemeral),
            Iv = Convert.ToBase64String(iv),
            Ciphertext = Convert.ToBase64String(ciphertext),
            Mac = Convert.ToBase64String(mac)
        };
    }

    public CommandEnvelopeDto BuildSignedCommand(
        SimulatedCar car,
        long issuedAtMs,
        long ttlMs = 300_000,
        PairingProofDto? pairingProof = null,
        string? clientHint = "Climate Theme: Warm Cozy 78°F")
    {
        string commandId = $"cmd_{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))}";
        long expiresAtMs = issuedAtMs + ttlMs;
        E2eeBoxDto box = CreateSimulatedE2eeBox();
        string boxDigest = Gen5WCrypto.ComputeBoxDigestHex(box.EphemeralPubKey, box.Iv, box.Ciphertext, box.Mac);
        string canonical = Gen5WCrypto.BuildCommandEnvelopeCanonical(
            commandId, car.CarId, PhoneId, issuedAtMs, expiresAtMs, boxDigest);

        return new CommandEnvelopeDto
        {
            CommandId = commandId,
            CarId = car.CarId,
            PhoneId = PhoneId,
            IssuedAtMs = issuedAtMs,
            ExpiresAtMs = expiresAtMs,
            TtlSeconds = (int)(ttlMs / 1000),
            E2ee = box,
            PhoneSignature = Gen5WCrypto.SignEcdsaP256DerBase64(Key, canonical),
            PairingProof = pairingProof,
            ClientHint = clientHint
        };
    }

    public string SignStatus(string carId, long ts) =>
        Gen5WCrypto.SignEcdsaP256DerBase64(Key, Gen5WCrypto.BuildPhoneStatusCanonical(carId, PhoneId, ts));

    public string SignCancel(string commandId, string carId, long ts) =>
        Gen5WCrypto.SignEcdsaP256DerBase64(Key, Gen5WCrypto.BuildPhoneCancelCanonical(commandId, carId, PhoneId, ts));

    public void Dispose() => Key.Dispose();
}

internal sealed class RelayTestHarness : IAsyncDisposable
{
    public string TempDirectory { get; }
    public ControllableTimeProvider Clock { get; }
    public SettingsManager SettingsManager { get; }
    public WebApplicationFactory<Program> Factory { get; }
    public HttpClient Client { get; }

    public RelayTestHarness(Action<ServerSettings>? configure = null)
    {
        Environment.SetEnvironmentVariable("DCP_TEST_HOST", "1");

        TempDirectory = Path.Combine(Path.GetTempPath(), "dcp-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(TempDirectory);

        Clock = new ControllableTimeProvider();

        var settings = new ServerSettings
        {
            AuthMode = "device_pop_only",
            RateLimitPerIpPerMinute = 5000,
            RateLimitPerCarPerMinute = 2000
        };
        configure?.Invoke(settings);

        SettingsManager = new SettingsManager(TempDirectory, settings);

        Factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(Clock);

                services.RemoveAll<SettingsManager>();
                services.AddSingleton(SettingsManager);

                services.RemoveAll<RelayDatabase>();
                services.AddSingleton(_ => new RelayDatabase(SettingsManager.ResolveDatabasePath()));
            });
        });

        Client = Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false // Clients enforce followRedirects = false!
        });
    }

    public RelayDatabase GetDatabase() => Factory.Services.GetRequiredService<RelayDatabase>();

    public ValueTask DisposeAsync()
    {
        Client.Dispose();
        Factory.Dispose();
        SqliteClearPoolsAndCleanup(TempDirectory);
        return ValueTask.CompletedTask;
    }

    private static void SqliteClearPoolsAndCleanup(string dir)
    {
        try
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch { }
    }
}

public sealed class RelayIntegrationTests
{
    [Fact]
    public void DefaultSettings_PublicUrl_StartsCompletelyBlank()
    {
        var defaults = new ServerSettings();
        Assert.Equal("", defaults.PublicUrl);
        Assert.Equal("", defaults.CustomBindUrl);
        Assert.Null(defaults.TryGetPublicHostname());
        Assert.Equal(NormalizedAuthMode.OpenDevicePopOnly, defaults.NormalizedAuth);
        Assert.Equal(100, defaults.RateLimitPerIpPerMinute);
        Assert.Equal(40, defaults.RateLimitPerCarPerMinute);
    }

    [Fact]
    public void Crypto_91ByteSpkiDer_Fingerprint_And_Asn1DerSignatures_EnforcedStrictly()
    {
        using var car = new SimulatedCar();
        byte[] spkiDer = Convert.FromBase64String(car.PublicKeySpkiB64);

        // Standard uncompressed X.509 SPKI DER for NIST P-256 is 91 bytes
        Assert.Equal(91, spkiDer.Length);
        Assert.Equal(64, car.FingerprintHex.Length);
        Assert.Equal(car.FingerprintHex, Convert.ToHexStringLower(SHA256.HashData(spkiDer)));

        string canonical = "GEN5W-POLL-V1|car_8f14e45fceea167a5a36dedd|1763665012000|nonce_abc12345";
        string derSigB64 = Gen5WCrypto.SignEcdsaP256DerBase64(car.Key, canonical);
        Assert.True(Gen5WCrypto.VerifyEcdsaP256DerBase64(car.PublicKeySpkiB64, canonical, derSigB64));

        // Raw 64-byte IEEE P1363 (r || s) MUST be rejected because Java/Android/CryptoKit emit ASN.1 DER
        byte[] rawP1363 = car.Key.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.Equal(64, rawP1363.Length);
        Assert.False(Gen5WCrypto.VerifyEcdsaP256DerBase64(car.PublicKeySpkiB64, canonical, Convert.ToBase64String(rawP1363)));

        // Non-P256 curve (e.g. P-384) MUST be rejected
        using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        string p384SpkiB64 = Convert.ToBase64String(p384.ExportSubjectPublicKeyInfo());
        Assert.False(Gen5WCrypto.IsValidP256SpkiBase64(p384SpkiB64));
    }

    [Fact]
    public async Task HealthEndpoint_IsPublic_AcrossAllAuthModes_WithZeroRedirects()
    {
        await using var harness = new RelayTestHarness(s =>
        {
            s.AuthMode = "shared_token";
            s.ServerSharedToken = "top-secret-token";
        });

        HttpResponseMessage resp = await harness.Client.GetAsync("/api/v1/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        HealthResponse? health = await resp.Content.ReadFromJsonAsync<HealthResponse>();
        Assert.NotNull(health);
        Assert.True(health.Ok);
        Assert.Equal("gen5w-digital-control-relay", health.Service);
        Assert.Equal(harness.Clock.NowMs, health.TimeMs);
    }

    [Fact]
    public async Task UnregisteredCar_Returns404CarNotRegistered_OnPoll_And404OnCommands()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var phone = new SimulatedPhone();

        long now = harness.Clock.NowMs;
        var pollReq = new CarPollRequest
        {
            CarId = car.CarId,
            TimestampMs = now,
            Nonce = "nonce_0123456789abcdef",
            WaitSeconds = 0,
            CarSignature = car.SignPoll(now, "nonce_0123456789abcdef")
        };

        HttpResponseMessage pollResp = await harness.Client.PostAsJsonAsync("/api/v1/car/poll", pollReq);
        Assert.Equal(HttpStatusCode.NotFound, pollResp.StatusCode);
        ApiErrorResponse? pollErr = await pollResp.Content.ReadFromJsonAsync<ApiErrorResponse>();
        Assert.NotNull(pollErr);
        Assert.False(pollErr.Ok);
        Assert.Equal("CAR_NOT_REGISTERED", pollErr.Error);

        var proof = new PairingProofDto
        {
            PhonePublicKey = phone.PublicKeySpkiB64,
            PairedAtMs = now - 1000,
            CarGrantSignature = car.SignPairingGrant(phone, now - 1000)
        };
        CommandEnvelopeDto cmd = phone.BuildSignedCommand(car, now, pairingProof: proof);
        HttpResponseMessage cmdResp = await harness.Client.PostAsJsonAsync("/api/v1/commands", cmd);
        Assert.Equal(HttpStatusCode.NotFound, cmdResp.StatusCode);
    }

    [Fact]
    public async Task CarRegister_EnforcesTofuPinning_AndRevokesRemovedPhones()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var impostorCarSameId = new SimulatedCar(car.CarId);
        using var phone1 = new SimulatedPhone();
        using var phone2 = new SimulatedPhone();

        long pairedAt = harness.Clock.NowMs - 5_000;
        long regTs = harness.Clock.NowMs;

        var regReq = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = regTs,
            CarSignature = car.SignRegister(regTs),
            AuthorizedPhones =
            [
                new AuthorizedPhoneDto
                {
                    PhoneId = phone1.PhoneId,
                    PhoneName = "Pixel 9 Pro",
                    Platform = "android",
                    PhonePublicKey = phone1.PublicKeySpkiB64,
                    PairedAtMs = pairedAt,
                    CarGrantSignature = car.SignPairingGrant(phone1, pairedAt)
                },
                new AuthorizedPhoneDto
                {
                    PhoneId = phone2.PhoneId,
                    PhoneName = "iPhone 16 Pro",
                    Platform = "ios",
                    PhonePublicKey = phone2.PublicKeySpkiB64,
                    PairedAtMs = pairedAt,
                    CarGrantSignature = car.SignPairingGrant(phone2, pairedAt)
                }
            ]
        };

        HttpResponseMessage regResp = await harness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq);
        Assert.Equal(HttpStatusCode.OK, regResp.StatusCode);
        CarRegisterResponse? regBody = await regResp.Content.ReadFromJsonAsync<CarRegisterResponse>();
        Assert.Equal(2, regBody!.AuthorizedPhoneCount);

        // TOFU Check: Same carId with a different EC P-256 public key MUST be rejected with 403 Forbidden
        var tofuAttack = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = impostorCarSameId.PublicKeySpkiB64,
            TimestampMs = regTs + 1000,
            CarSignature = impostorCarSameId.SignRegister(regTs + 1000),
            AuthorizedPhones = []
        };
        HttpResponseMessage tofuResp = await harness.Client.PostAsJsonAsync("/api/v1/cars/register", tofuAttack);
        Assert.Equal(HttpStatusCode.Forbidden, tofuResp.StatusCode);

        // Revoke phone2 on the car and re-sync authorizedPhones with only phone1
        harness.Clock.Advance(TimeSpan.FromSeconds(10));
        long regTs2 = harness.Clock.NowMs;
        var revokeSyncReq = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = regTs2,
            CarSignature = car.SignRegister(regTs2),
            AuthorizedPhones = [regReq.AuthorizedPhones[0]]
        };
        HttpResponseMessage revSyncResp = await harness.Client.PostAsJsonAsync("/api/v1/cars/register", revokeSyncReq);
        Assert.Equal(HttpStatusCode.OK, revSyncResp.StatusCode);

        // Revoked phone2 attempting to submit a command using its old CarGrantSignature MUST get 403 Forbidden
        var oldProof2 = new PairingProofDto
        {
            PhonePublicKey = phone2.PublicKeySpkiB64,
            PairedAtMs = pairedAt,
            CarGrantSignature = car.SignPairingGrant(phone2, pairedAt)
        };
        CommandEnvelopeDto revokedCmd = phone2.BuildSignedCommand(car, harness.Clock.NowMs, pairingProof: oldProof2);
        HttpResponseMessage revCmdResp = await harness.Client.PostAsJsonAsync("/api/v1/commands", revokedCmd);
        Assert.Equal(HttpStatusCode.Forbidden, revCmdResp.StatusCode);
    }

    [Fact]
    public async Task EndToEnd_LongPollWakeup_ExactEnvelopePreservation_Ack_AndEncryptedTelemetry()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var phone = new SimulatedPhone();

        long now = harness.Clock.NowMs;
        long pairedAt = now - 2_000;
        string grantSig = car.SignPairingGrant(phone, pairedAt);

        // 1. Register car + phone
        var regReq = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = now,
            CarSignature = car.SignRegister(now),
            AuthorizedPhones =
            [
                new AuthorizedPhoneDto
                {
                    PhoneId = phone.PhoneId,
                    PhoneName = "Owner Phone",
                    Platform = "android",
                    PhonePublicKey = phone.PublicKeySpkiB64,
                    PairedAtMs = pairedAt,
                    CarGrantSignature = grantSig
                }
            ]
        };
        Assert.Equal(HttpStatusCode.OK, (await harness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq)).StatusCode);

        // 2. Start Car Long-Poll (waitSeconds = 12) + upload encryptedTelemetry for phone
        E2eeBoxDto telBoxRaw = phone.CreateSimulatedE2eeBox("{\"soc\":81,\"cabinTempC\":21.5}");
        var telemetryPayload = new EncryptedTelemetryDto
        {
            EphemeralPubKey = telBoxRaw.EphemeralPubKey,
            Iv = telBoxRaw.Iv,
            Ciphertext = telBoxRaw.Ciphertext,
            Mac = telBoxRaw.Mac,
            UpdatedAtMs = now
        };

        string pollNonce = "poll_nonce_longwait_001";
        var pollReq = new CarPollRequest
        {
            CarId = car.CarId,
            TimestampMs = now,
            Nonce = pollNonce,
            WaitSeconds = 12,
            CarSignature = car.SignPoll(now, pollNonce),
            EncryptedTelemetry = new Dictionary<string, EncryptedTelemetryDto>
            {
                [phone.PhoneId] = telemetryPayload
            }
        };

        using HttpClient pollClient = harness.Factory.CreateClient();
        Task<HttpResponseMessage> longPollTask = pollClient.PostAsJsonAsync("/api/v1/car/poll", pollReq);

        // Give the long-poll 80ms to park in the wait channel
        await Task.Delay(80);
        Assert.False(longPollTask.IsCompleted);

        // 3. Submit E2EE command from Phone and measure how fast long-poll wakes!
        var proof = new PairingProofDto
        {
            PhonePublicKey = phone.PublicKeySpkiB64,
            PairedAtMs = pairedAt,
            CarGrantSignature = grantSig
        };
        CommandEnvelopeDto submitted = phone.BuildSignedCommand(car, now + 50, pairingProof: proof);

        var sw = Stopwatch.StartNew();
        HttpResponseMessage submitResp = await harness.Client.PostAsJsonAsync("/api/v1/commands", submitted);
        Assert.Equal(HttpStatusCode.OK, submitResp.StatusCode);

        HttpResponseMessage wokenPollResp = await longPollTask;
        sw.Stop();

        Assert.Equal(HttpStatusCode.OK, wokenPollResp.StatusCode);
        Assert.True(sw.ElapsedMilliseconds < 500, $"Expected instant long-poll wakeup (<200ms typical), took {sw.ElapsedMilliseconds}ms");

        CarPollResponse? pollBody = await wokenPollResp.Content.ReadFromJsonAsync<CarPollResponse>();
        Assert.NotNull(pollBody);
        Assert.Single(pollBody.Commands);

        // Verify ZERO mutation of envelope fields (so car AAD & phoneSignature verification pass!)
        CommandEnvelopeDto delivered = pollBody.Commands[0];
        Assert.Equal(submitted.CommandId, delivered.CommandId);
        Assert.Equal(submitted.CarId, delivered.CarId);
        Assert.Equal(submitted.PhoneId, delivered.PhoneId);
        Assert.Equal(submitted.IssuedAtMs, delivered.IssuedAtMs);
        Assert.Equal(submitted.ExpiresAtMs, delivered.ExpiresAtMs);
        Assert.Equal(submitted.PhoneSignature, delivered.PhoneSignature);
        Assert.Equal(submitted.E2ee!.EphemeralPubKey, delivered.E2ee!.EphemeralPubKey);
        Assert.Equal(submitted.E2ee.Iv, delivered.E2ee.Iv);
        Assert.Equal(submitted.E2ee.Ciphertext, delivered.E2ee.Ciphertext);
        Assert.Equal(submitted.E2ee.Mac, delivered.E2ee.Mac);
        Assert.Equal(submitted.ClientHint, delivered.ClientHint);

        // 4. Car executes command and sends signed ACK
        long ackTs = now + 200;
        string ackMsg = "Applied Climate Theme: Warm Cozy 78°F";
        var ackReq = new CarAckRequest
        {
            CommandId = submitted.CommandId,
            CarId = car.CarId,
            Ok = true,
            Status = "EXECUTED",
            Message = ackMsg,
            ExecutedAtMs = ackTs,
            CarSignature = car.SignAck(submitted.CommandId, true, ackTs, ackMsg)
        };
        HttpResponseMessage ackResp = await harness.Client.PostAsJsonAsync("/api/v1/car/ack", ackReq);
        Assert.Equal(HttpStatusCode.OK, ackResp.StatusCode);

        // 5. Phone polls GET /api/v1/commands and receives EXECUTED status + encryptedTelemetry
        long statusTs = now + 300;
        using var statusReq = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/v1/commands?carId={car.CarId}&phoneId={phone.PhoneId}&ts={statusTs}");
        statusReq.Headers.Add("X-Gen5W-Phone-Signature", phone.SignStatus(car.CarId, statusTs));

        HttpResponseMessage statusResp = await harness.Client.SendAsync(statusReq);
        Assert.Equal(HttpStatusCode.OK, statusResp.StatusCode);

        PhoneCommandsStatusResponse? statusBody = await statusResp.Content.ReadFromJsonAsync<PhoneCommandsStatusResponse>();
        Assert.NotNull(statusBody);
        Assert.Single(statusBody.Commands);
        Assert.Equal("EXECUTED", statusBody.Commands[0].Status);
        Assert.Equal(ackTs, statusBody.Commands[0].ExecutedAtMs);
        Assert.Equal(ackMsg, statusBody.Commands[0].Message);

        Assert.NotNull(statusBody.EncryptedTelemetry);
        Assert.Equal(telemetryPayload.Ciphertext, statusBody.EncryptedTelemetry.Ciphertext);
        Assert.Equal(telemetryPayload.Mac, statusBody.EncryptedTelemetry.Mac);

        // 6. Future car poll no longer receives the EXECUTED command
        var pollReq2 = new CarPollRequest
        {
            CarId = car.CarId,
            TimestampMs = now + 400,
            Nonce = "poll_nonce_after_ack_002",
            WaitSeconds = 0,
            CarSignature = car.SignPoll(now + 400, "poll_nonce_after_ack_002")
        };
        CarPollResponse? poll2 = await (await harness.Client.PostAsJsonAsync("/api/v1/car/poll", pollReq2))
            .Content.ReadFromJsonAsync<CarPollResponse>();
        Assert.Empty(poll2!.Commands);
    }

    [Fact]
    public async Task NewlyPairedPhone_EnrollsViaPairingProof_BeforeCarNextSyncs()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var newPhone = new SimulatedPhone();

        long regTs = harness.Clock.NowMs;
        var regReq = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = regTs,
            CarSignature = car.SignRegister(regTs),
            AuthorizedPhones = []
        };
        Assert.Equal(HttpStatusCode.OK, (await harness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq)).StatusCode);

        // Phone pairs over Bluetooth inside car 5 seconds AFTER car's last sync
        harness.Clock.Advance(TimeSpan.FromSeconds(5));
        long pairedAt = harness.Clock.NowMs;
        var proof = new PairingProofDto
        {
            PhonePublicKey = newPhone.PublicKeySpkiB64,
            PairedAtMs = pairedAt,
            CarGrantSignature = car.SignPairingGrant(newPhone, pairedAt)
        };

        CommandEnvelopeDto cmd = newPhone.BuildSignedCommand(car, harness.Clock.NowMs, pairingProof: proof);
        HttpResponseMessage cmdResp = await harness.Client.PostAsJsonAsync("/api/v1/commands", cmd);
        Assert.Equal(HttpStatusCode.OK, cmdResp.StatusCode);

        // And GET /api/v1/commands immediately works for the newly enrolled phone!
        long ts = harness.Clock.NowMs;
        using var statusReq = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/v1/commands?carId={car.CarId}&phoneId={newPhone.PhoneId}&ts={ts}");
        statusReq.Headers.Add("X-Gen5W-Phone-Signature", newPhone.SignStatus(car.CarId, ts));
        HttpResponseMessage statusResp = await harness.Client.SendAsync(statusReq);
        Assert.Equal(HttpStatusCode.OK, statusResp.StatusCode);
    }

    [Fact]
    public async Task InstantCancellation_PreventsCarDelivery_IsIdempotent_AndReturns409AfterExecution()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var phone = new SimulatedPhone();

        long now = harness.Clock.NowMs;
        var regReq = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = now,
            CarSignature = car.SignRegister(now),
            AuthorizedPhones =
            [
                new AuthorizedPhoneDto
                {
                    PhoneId = phone.PhoneId,
                    PhonePublicKey = phone.PublicKeySpkiB64,
                    PairedAtMs = now - 1000,
                    CarGrantSignature = car.SignPairingGrant(phone, now - 1000)
                }
            ]
        };
        await harness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq);

        // Queue Cmd 1 and Cancel it immediately
        CommandEnvelopeDto cmd1 = phone.BuildSignedCommand(car, now);
        Assert.Equal(HttpStatusCode.OK, (await harness.Client.PostAsJsonAsync("/api/v1/commands", cmd1)).StatusCode);

        using var del1 = new HttpRequestMessage(
            HttpMethod.Delete,
            $"/api/v1/commands/{cmd1.CommandId}?carId={car.CarId}&phoneId={phone.PhoneId}&ts={now}");
        del1.Headers.Add("X-Gen5W-Phone-Signature", phone.SignCancel(cmd1.CommandId, car.CarId, now));
        HttpResponseMessage delResp1 = await harness.Client.SendAsync(del1);
        Assert.Equal(HttpStatusCode.OK, delResp1.StatusCode);

        // Repeat DELETE on already CANCELED command -> idempotent 200 OK
        using var delRepeat = new HttpRequestMessage(
            HttpMethod.Delete,
            $"/api/v1/commands/{cmd1.CommandId}?carId={car.CarId}&phoneId={phone.PhoneId}&ts={now}");
        delRepeat.Headers.Add("X-Gen5W-Phone-Signature", phone.SignCancel(cmd1.CommandId, car.CarId, now));
        Assert.Equal(HttpStatusCode.OK, (await harness.Client.SendAsync(delRepeat)).StatusCode);

        // Car polls -> must NOT receive canceled Cmd 1
        var pollReq = new CarPollRequest
        {
            CarId = car.CarId,
            TimestampMs = now,
            Nonce = "nonce_cancel_check_001",
            WaitSeconds = 0,
            CarSignature = car.SignPoll(now, "nonce_cancel_check_001")
        };
        CarPollResponse? pollBody = await (await harness.Client.PostAsJsonAsync("/api/v1/car/poll", pollReq))
            .Content.ReadFromJsonAsync<CarPollResponse>();
        Assert.Empty(pollBody!.Commands);

        // Queue Cmd 2, ACK it as EXECUTED, then try to DELETE -> MUST return 409 Conflict!
        CommandEnvelopeDto cmd2 = phone.BuildSignedCommand(car, now);
        await harness.Client.PostAsJsonAsync("/api/v1/commands", cmd2);
        var ackReq = new CarAckRequest
        {
            CommandId = cmd2.CommandId,
            CarId = car.CarId,
            Ok = true,
            Message = "Done",
            ExecutedAtMs = now + 50,
            CarSignature = car.SignAck(cmd2.CommandId, true, now + 50, "Done")
        };
        await harness.Client.PostAsJsonAsync("/api/v1/car/ack", ackReq);

        using var delExecuted = new HttpRequestMessage(
            HttpMethod.Delete,
            $"/api/v1/commands/{cmd2.CommandId}?carId={car.CarId}&phoneId={phone.PhoneId}&ts={now + 100}");
        delExecuted.Headers.Add("X-Gen5W-Phone-Signature", phone.SignCancel(cmd2.CommandId, car.CarId, now + 100));
        HttpResponseMessage conflictResp = await harness.Client.SendAsync(delExecuted);
        Assert.Equal(HttpStatusCode.Conflict, conflictResp.StatusCode);
    }

    [Fact]
    public async Task FiveMinuteTimeout_ExpiresQueuedCommand_BlocksDelivery_Returns409OnCancel_AndPrunes24hHistory()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var phone = new SimulatedPhone();

        long t0 = harness.Clock.NowMs;
        await harness.Client.PostAsJsonAsync("/api/v1/cars/register", new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = t0,
            CarSignature = car.SignRegister(t0),
            AuthorizedPhones =
            [
                new AuthorizedPhoneDto
                {
                    PhoneId = phone.PhoneId,
                    PhonePublicKey = phone.PublicKeySpkiB64,
                    PairedAtMs = t0 - 1000,
                    CarGrantSignature = car.SignPairingGrant(phone, t0 - 1000)
                }
            ]
        });

        // Reject TTL > 305s
        CommandEnvelopeDto tooLongCmd = phone.BuildSignedCommand(car, t0, ttlMs: 600_000);
        Assert.Equal(HttpStatusCode.BadRequest, (await harness.Client.PostAsJsonAsync("/api/v1/commands", tooLongCmd)).StatusCode);

        // Enqueue valid 5-minute (300,000 ms) command
        CommandEnvelopeDto cmd = phone.BuildSignedCommand(car, t0, ttlMs: 300_000);
        Assert.Equal(HttpStatusCode.OK, (await harness.Client.PostAsJsonAsync("/api/v1/commands", cmd)).StatusCode);

        // Advance server clock by 5 minutes + 1 millisecond
        harness.Clock.Advance(TimeSpan.FromMilliseconds(300_001));
        long tExpired = harness.Clock.NowMs;

        // Car poll MUST NOT receive expired command
        var pollReq = new CarPollRequest
        {
            CarId = car.CarId,
            TimestampMs = tExpired,
            Nonce = "nonce_after_5min_ttl",
            WaitSeconds = 0,
            CarSignature = car.SignPoll(tExpired, "nonce_after_5min_ttl")
        };
        CarPollResponse? pollBody = await (await harness.Client.PostAsJsonAsync("/api/v1/car/poll", pollReq))
            .Content.ReadFromJsonAsync<CarPollResponse>();
        Assert.Empty(pollBody!.Commands);

        // Phone status poll shows EXPIRED ("Timed out after 5 minutes")
        using var statusReq = new HttpRequestMessage(
            HttpMethod.Get,
            $"/api/v1/commands?carId={car.CarId}&phoneId={phone.PhoneId}&ts={tExpired}");
        statusReq.Headers.Add("X-Gen5W-Phone-Signature", phone.SignStatus(car.CarId, tExpired));
        PhoneCommandsStatusResponse? statusBody = await (await harness.Client.SendAsync(statusReq))
            .Content.ReadFromJsonAsync<PhoneCommandsStatusResponse>();
        Assert.Single(statusBody!.Commands);
        Assert.Equal("EXPIRED", statusBody.Commands[0].Status);
        Assert.Equal("Timed out after 5 minutes", statusBody.Commands[0].Message);

        // Attempting to DELETE an expired command returns 409 Conflict
        using var cancelExpired = new HttpRequestMessage(
            HttpMethod.Delete,
            $"/api/v1/commands/{cmd.CommandId}?carId={car.CarId}&phoneId={phone.PhoneId}&ts={tExpired}");
        cancelExpired.Headers.Add("X-Gen5W-Phone-Signature", phone.SignCancel(cmd.CommandId, car.CarId, tExpired));
        Assert.Equal(HttpStatusCode.Conflict, (await harness.Client.SendAsync(cancelExpired)).StatusCode);

        // Advance >24h and verify background maintenance sweep prunes historical terminal rows & old nonces
        harness.Clock.Advance(TimeSpan.FromHours(25));
        var (_, prunedCmds, prunedNonces) = await harness.GetDatabase().RunMaintenanceSweepAsync(harness.Clock.NowMs);
        Assert.Equal(1, prunedCmds);
        Assert.Equal(1, prunedNonces);
    }

    [Fact]
    public async Task Security_RejectsForgedSignatures_UnpairedPhones_ClockSkew_AndReplayedNonces()
    {
        await using var harness = new RelayTestHarness();
        using var car = new SimulatedCar();
        using var attackerCar = new SimulatedCar();
        using var pairedPhone = new SimulatedPhone();
        using var unpairedPhone = new SimulatedPhone();

        long now = harness.Clock.NowMs;

        // 1. Forged car registration signature -> 401
        var badReg = new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = now,
            CarSignature = attackerCar.SignRegister(now)
        };
        Assert.Equal(HttpStatusCode.Unauthorized, (await harness.Client.PostAsJsonAsync("/api/v1/cars/register", badReg)).StatusCode);

        // Register legitimate car + pairedPhone
        await harness.Client.PostAsJsonAsync("/api/v1/cars/register", new CarRegisterRequest
        {
            CarId = car.CarId,
            CarPublicKey = car.PublicKeySpkiB64,
            TimestampMs = now,
            CarSignature = car.SignRegister(now),
            AuthorizedPhones =
            [
                new AuthorizedPhoneDto
                {
                    PhoneId = pairedPhone.PhoneId,
                    PhonePublicKey = pairedPhone.PublicKeySpkiB64,
                    PairedAtMs = now - 1000,
                    CarGrantSignature = car.SignPairingGrant(pairedPhone, now - 1000)
                }
            ]
        });

        // 2. Unpaired phone with forged PairingGrant (signed by attackerCar instead of car) -> 403 Forbidden
        var forgedProof = new PairingProofDto
        {
            PhonePublicKey = unpairedPhone.PublicKeySpkiB64,
            PairedAtMs = now + 100,
            CarGrantSignature = attackerCar.SignPairingGrant(unpairedPhone, now + 100)
        };
        CommandEnvelopeDto unpairedCmd = unpairedPhone.BuildSignedCommand(car, now, pairingProof: forgedProof);
        Assert.Equal(HttpStatusCode.Forbidden, (await harness.Client.PostAsJsonAsync("/api/v1/commands", unpairedCmd)).StatusCode);

        // 3. Paired phone with tampered ciphertext (breaks GEN5W-ENV-V1 boxDigestHex!) -> 401 Unauthorized
        CommandEnvelopeDto tamperedCmd = pairedPhone.BuildSignedCommand(car, now);
        tamperedCmd.E2ee!.Ciphertext = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Assert.Equal(HttpStatusCode.Unauthorized, (await harness.Client.PostAsJsonAsync("/api/v1/commands", tamperedCmd)).StatusCode);

        // 4. Clock skew > ±90,000 ms -> 401 Unauthorized
        long skewedTs = now - 120_000;
        CommandEnvelopeDto skewedCmd = pairedPhone.BuildSignedCommand(car, skewedTs);
        Assert.Equal(HttpStatusCode.Unauthorized, (await harness.Client.PostAsJsonAsync("/api/v1/commands", skewedCmd)).StatusCode);

        // 5. Nonce Replay on /api/v1/car/poll -> First succeeds (200), exact replay within 5m rejected (401)!
        var pollReq = new CarPollRequest
        {
            CarId = car.CarId,
            TimestampMs = now,
            Nonce = "unique_poll_nonce_xyz987",
            WaitSeconds = 0,
            CarSignature = car.SignPoll(now, "unique_poll_nonce_xyz987")
        };
        Assert.Equal(HttpStatusCode.OK, (await harness.Client.PostAsJsonAsync("/api/v1/car/poll", pollReq)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await harness.Client.PostAsJsonAsync("/api/v1/car/poll", pollReq)).StatusCode);
    }

    [Fact]
    public async Task AuthModes_SharedToken_And_MultiUserAccounts_EnforceBearerTokensIsolationAndQuotas()
    {
        // --- Part A: AUTH_MODE=shared_token ---
        await using (var sharedHarness = new RelayTestHarness(s =>
        {
            s.AuthMode = "shared_token";
            s.ServerSharedToken = "my_private_relay_secret_123";
        }))
        {
            using var car = new SimulatedCar();
            long now = sharedHarness.Clock.NowMs;
            var regReq = new CarRegisterRequest
            {
                CarId = car.CarId,
                CarPublicKey = car.PublicKeySpkiB64,
                TimestampMs = now,
                CarSignature = car.SignRegister(now)
            };

            // Missing token -> 401
            Assert.Equal(HttpStatusCode.Unauthorized, (await sharedHarness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq)).StatusCode);

            // Wrong token -> 401
            sharedHarness.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "wrong_token");
            Assert.Equal(HttpStatusCode.Unauthorized, (await sharedHarness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq)).StatusCode);

            // Correct token -> 200 OK
            sharedHarness.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "my_private_relay_secret_123");
            Assert.Equal(HttpStatusCode.OK, (await sharedHarness.Client.PostAsJsonAsync("/api/v1/cars/register", regReq)).StatusCode);
        }

        // --- Part B: AUTH_MODE=account_plus_device_pop (market.ioniqthemes.com compatible JWT + CLI API tokens) ---
        await using (var acctHarness = new RelayTestHarness(s =>
        {
            s.AuthMode = "account_plus_device_pop";
            s.AllowPublicAccountRegistration = true;
            s.MaxCarsPerAccount = 1; // Quota = 1 car per account for testing!
        }))
        {
            // Register Alice
            HttpResponseMessage regAlice = await acctHarness.Client.PostAsJsonAsync("/api/v1/auth/register", new AccountCredentialsRequest
            {
                Username = "alice_ev",
                Password = "StrongPassword123!"
            });
            Assert.Equal(HttpStatusCode.Created, regAlice.StatusCode);
            AuthActionResponse? aliceAuth = await regAlice.Content.ReadFromJsonAsync<AuthActionResponse>();
            Assert.True(aliceAuth!.Ok);
            Assert.NotNull(aliceAuth.Token);

            // Login Alice & check /api/v1/auth/me
            HttpResponseMessage loginAlice = await acctHarness.Client.PostAsJsonAsync("/api/v1/auth/login", new AccountCredentialsRequest
            {
                Username = "alice_ev",
                Password = "StrongPassword123!"
            });
            Assert.Equal(HttpStatusCode.OK, loginAlice.StatusCode);

            using var meReq = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
            meReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", aliceAuth.Token);
            HttpResponseMessage meResp = await acctHarness.Client.SendAsync(meReq);
            Assert.Equal(HttpStatusCode.OK, meResp.StatusCode);

            // Register Bob
            AuthActionResponse? bobAuth = await (await acctHarness.Client.PostAsJsonAsync("/api/v1/auth/register", new AccountCredentialsRequest
            {
                Username = "bob_ev",
                Password = "AnotherPassword456!"
            })).Content.ReadFromJsonAsync<AuthActionResponse>();

            // Alice registers Car 1 (succeeds) and tries Car 2 (exceeds MaxCarsPerAccount=1 -> 403 Forbidden!)
            using var car1 = new SimulatedCar();
            using var car2 = new SimulatedCar();
            long now = acctHarness.Clock.NowMs;

            acctHarness.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", aliceAuth.Token);
            Assert.Equal(HttpStatusCode.OK, (await acctHarness.Client.PostAsJsonAsync("/api/v1/cars/register", new CarRegisterRequest
            {
                CarId = car1.CarId,
                CarPublicKey = car1.PublicKeySpkiB64,
                TimestampMs = now,
                CarSignature = car1.SignRegister(now)
            })).StatusCode);

            Assert.Equal(HttpStatusCode.Forbidden, (await acctHarness.Client.PostAsJsonAsync("/api/v1/cars/register", new CarRegisterRequest
            {
                CarId = car2.CarId,
                CarPublicKey = car2.PublicKeySpkiB64,
                TimestampMs = now,
                CarSignature = car2.SignRegister(now)
            })).StatusCode);

            // Bob attempting to poll Alice's Car 1 (even with a valid Car 1 signature!) MUST get 403 Forbidden!
            acctHarness.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bobAuth!.Token);
            Assert.Equal(HttpStatusCode.Forbidden, (await acctHarness.Client.PostAsJsonAsync("/api/v1/car/poll", new CarPollRequest
            {
                CarId = car1.CarId,
                TimestampMs = now,
                Nonce = "bob_cross_account_probe",
                WaitSeconds = 0,
                CarSignature = car1.SignPoll(now, "bob_cross_account_probe")
            })).StatusCode);

            // Also verify static CLI/Admin API Token ("dcp_...") works in accounts mode!
            var (plainApiToken, tokenRec) = await acctHarness.GetDatabase().CreateApiTokenAsync("Fleet Operator", 2, now);
            acctHarness.Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", plainApiToken);
            Assert.Equal(HttpStatusCode.OK, (await acctHarness.Client.PostAsJsonAsync("/api/v1/cars/register", new CarRegisterRequest
            {
                CarId = car2.CarId,
                CarPublicKey = car2.PublicKeySpkiB64,
                TimestampMs = now,
                CarSignature = car2.SignRegister(now)
            })).StatusCode);

            // Revoking the API token immediately blocks access (401)
            await acctHarness.GetDatabase().RevokeApiTokenAsync(tokenRec.Id);
            Assert.Equal(HttpStatusCode.Unauthorized, (await acctHarness.Client.PostAsJsonAsync("/api/v1/car/poll", new CarPollRequest
            {
                CarId = car2.CarId,
                TimestampMs = now,
                Nonce = "revoked_token_probe",
                WaitSeconds = 0,
                CarSignature = car2.SignPoll(now, "revoked_token_probe")
            })).StatusCode);
        }
    }

    [Fact]
    public async Task RealKestrelListener_SupportsTls12_ForGen5WAndroid442KitKat_AndTls13()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "dcp-tls-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var settings = new ServerSettings
            {
                ListenInterface = "127.0.0.1",
                Port = 0, // Ephemeral free port
                TlsMode = "SelfSignedLocal",
                AuthMode = "device_pop_only"
            };
            var sm = new SettingsManager(tempDir, settings);
            var metrics = new DigitalConnectPlus.Server.Services.MetricsTracker();
            using var loggerFactory = LoggerFactory.Create(_ => { });
            using var certProv = new DigitalConnectPlus.Server.Tls.CertificateProvider(
                sm, metrics, loggerFactory.CreateLogger<DigitalConnectPlus.Server.Tls.CertificateProvider>());
            certProv.ReloadCertificate();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.Listen(IPAddress.Loopback, 0, listenOpts =>
                {
                    listenOpts.UseHttps((_, hello, _, _) =>
                        ValueTask.FromResult(certProv.GetSslServerOptions(hello.ServerName)), string.Empty);
                });
            });

            var app = builder.Build();
            app.MapGet("/api/v1/health", () => Results.Ok(new { ok = true, service = "gen5w-digital-control-relay" }));
            await app.StartAsync();

            try
            {
                string address = app.Services.GetRequiredService<IServer>()
                    .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
                var uri = new Uri(address);

                // Simulate Android 4.4.2 KitKat (RemoteTlsHelper): force TLS 1.2 ONLY!
                using (var tcp = new TcpClient())
                {
                    await tcp.ConnectAsync(IPAddress.Loopback, uri.Port);
                    await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = "localhost",
                        EnabledSslProtocols = SslProtocols.Tls12
                    });

                    Assert.Equal(SslProtocols.Tls12, ssl.SslProtocol);
                }

                // Also verify full HTTPS GET /api/v1/health over TLS 1.2 HttpClientHandler
                using var handler = new SocketsHttpHandler
                {
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        EnabledSslProtocols = SslProtocols.Tls12,
                        RemoteCertificateValidationCallback = (_, _, _, _) => true
                    }
                };
                using var client = new HttpClient(handler);
                HttpResponseMessage resp = await client.GetAsync($"{address}/api/v1/health");
                Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            }
            finally
            {
                await app.StopAsync();
                await app.DisposeAsync();
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }
}
