using System.Security.Cryptography;
using System.Text.Json;
using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Models;
using DigitalConnectPlus.Server.Security;
using Microsoft.Data.Sqlite;

namespace DigitalConnectPlus.Server.Data;

public sealed record CarRecord(
    string CarId,
    string CarPublicKey,
    string KeyFingerprint,
    int? OwnerKeyId,
    long CreatedAtMs,
    long UpdatedAtMs,
    long LastRegisterTsMs,
    long LastSeenAtMs);

public sealed record AuthorizedPhoneRecord(
    string CarId,
    string PhoneId,
    string? PhoneName,
    string? Platform,
    string PhonePublicKey,
    string KeyFingerprint,
    long PairedAtMs,
    string CarGrantSignature);

public enum CarRegisterResultStatus
{
    Success,
    TofuKeyMismatch,
    AccountForbidden,
    AccountCarQuotaExceeded,
    StaleTimestampReplay
}

public enum EnqueueCommandStatus
{
    Queued,
    DuplicateCommandId,
    QueueLimitReached
}

public enum CancelCommandOutcome
{
    Canceled,
    NotFound,
    AlreadyTerminal
}

public sealed class RelayDatabase : IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _connectionString;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public string DatabasePath { get; }

    public RelayDatabase(string databasePath)
    {
        DatabasePath = Path.GetFullPath(databasePath);
        string? dir = Path.GetDirectoryName(DatabasePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = 5
        };
        _connectionString = csb.ToString();
    }

    private async Task<SqliteConnection> OpenConnectionAsync(CancellationToken ct = default)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        await using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;";
        await pragma.ExecuteNonQueryAsync(ct);
        return conn;
    }

    public async Task<byte[]> InitializeAsync(CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using (var walCmd = conn.CreateCommand())
            {
                walCmd.CommandText = """
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                    """;
                await walCmd.ExecuteNonQueryAsync(ct);
            }

            await using (var schemaCmd = conn.CreateCommand())
            {
                schemaCmd.CommandText = """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        applied_at_ms INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS server_secrets (
                        secret_key TEXT PRIMARY KEY,
                        secret_value BLOB NOT NULL,
                        updated_at_ms INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS accounts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                        password_hash BLOB NOT NULL,
                        password_salt BLOB NOT NULL,
                        hash_iterations INTEGER NOT NULL,
                        max_cars INTEGER NOT NULL DEFAULT 5,
                        token_version INTEGER NOT NULL DEFAULT 1,
                        is_disabled INTEGER NOT NULL DEFAULT 0,
                        created_at_ms INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS api_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        label TEXT NOT NULL,
                        token_hash_hex TEXT NOT NULL UNIQUE,
                        token_prefix TEXT NOT NULL,
                        account_id INTEGER NULL,
                        max_cars INTEGER NOT NULL DEFAULT 5,
                        is_revoked INTEGER NOT NULL DEFAULT 0,
                        created_at_ms INTEGER NOT NULL,
                        last_used_at_ms INTEGER NULL
                    );

                    CREATE TABLE IF NOT EXISTS cars (
                        car_id TEXT PRIMARY KEY,
                        car_public_key TEXT NOT NULL,
                        key_fingerprint TEXT NOT NULL,
                        owner_key_id INTEGER NULL,
                        created_at_ms INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        last_register_ts_ms INTEGER NOT NULL,
                        last_seen_at_ms INTEGER NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS ix_cars_owner ON cars(owner_key_id);

                    CREATE TABLE IF NOT EXISTS authorized_phones (
                        car_id TEXT NOT NULL,
                        phone_id TEXT NOT NULL,
                        phone_name TEXT NULL,
                        platform TEXT NULL,
                        phone_public_key TEXT NOT NULL,
                        key_fingerprint TEXT NOT NULL,
                        paired_at_ms INTEGER NOT NULL,
                        car_grant_signature TEXT NOT NULL,
                        PRIMARY KEY (car_id, phone_id),
                        FOREIGN KEY (car_id) REFERENCES cars(car_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS revoked_phones (
                        car_id TEXT NOT NULL,
                        phone_id TEXT NOT NULL,
                        revoked_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (car_id, phone_id),
                        FOREIGN KEY (car_id) REFERENCES cars(car_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS commands (
                        command_id TEXT PRIMARY KEY,
                        car_id TEXT NOT NULL,
                        phone_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        issued_at_ms INTEGER NOT NULL,
                        expires_at_ms INTEGER NOT NULL,
                        ttl_seconds INTEGER NOT NULL,
                        executed_at_ms INTEGER NOT NULL DEFAULT 0,
                        message TEXT NOT NULL,
                        envelope_json TEXT NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        FOREIGN KEY (car_id) REFERENCES cars(car_id) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS ix_commands_car_status_issued
                        ON commands(car_id, status, issued_at_ms ASC);

                    CREATE INDEX IF NOT EXISTS ix_commands_car_phone_issued
                        ON commands(car_id, phone_id, issued_at_ms DESC);

                    CREATE INDEX IF NOT EXISTS ix_commands_status_expires
                        ON commands(status, expires_at_ms);

                    CREATE TABLE IF NOT EXISTS telemetry_blobs (
                        car_id TEXT NOT NULL,
                        phone_id TEXT NOT NULL,
                        telemetry_json TEXT NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (car_id, phone_id),
                        FOREIGN KEY (car_id) REFERENCES cars(car_id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS poll_nonces (
                        car_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        expires_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (car_id, nonce)
                    );

                    CREATE INDEX IF NOT EXISTS ix_poll_nonces_expires
                        ON poll_nonces(expires_at_ms);

                    INSERT OR IGNORE INTO schema_migrations (version, applied_at_ms)
                    VALUES (1, unixepoch('now') * 1000);
                    """;
                await schemaCmd.ExecuteNonQueryAsync(ct);
            }

            // Load or initialize persistent 32-byte JWT signing key
            await using var getKeyCmd = conn.CreateCommand();
            getKeyCmd.CommandText = "SELECT secret_value FROM server_secrets WHERE secret_key = 'jwt_signing_key';";
            object? existing = await getKeyCmd.ExecuteScalarAsync(ct);
            if (existing is byte[] { Length: >= 32 } keyBytes)
                return keyBytes;

            byte[] generated = RandomNumberGenerator.GetBytes(32);
            await using var setKeyCmd = conn.CreateCommand();
            setKeyCmd.CommandText = """
                INSERT OR REPLACE INTO server_secrets (secret_key, secret_value, updated_at_ms)
                VALUES ('jwt_signing_key', $val, $now);
                """;
            setKeyCmd.Parameters.AddWithValue("$val", generated);
            setKeyCmd.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            await setKeyCmd.ExecuteNonQueryAsync(ct);
            return generated;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<CarRecord?> GetCarAsync(string carId, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT car_id, car_public_key, key_fingerprint, owner_key_id, created_at_ms, updated_at_ms, last_register_ts_ms, last_seen_at_ms
            FROM cars
            WHERE car_id = $carId;
            """;
        cmd.Parameters.AddWithValue("$carId", carId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            return null;

        return new CarRecord(
            CarId: reader.GetString(0),
            CarPublicKey: reader.GetString(1),
            KeyFingerprint: reader.GetString(2),
            OwnerKeyId: reader.IsDBNull(3) ? null : reader.GetInt32(3),
            CreatedAtMs: reader.GetInt64(4),
            UpdatedAtMs: reader.GetInt64(5),
            LastRegisterTsMs: reader.GetInt64(6),
            LastSeenAtMs: reader.GetInt64(7));
    }

    public async Task<CarRegisterResultStatus> RegisterOrUpdateCarAsync(
        string carId,
        string carPublicKey,
        string carKeyFingerprint,
        long timestampMs,
        long nowMs,
        List<AuthorizedPhoneRecord> authorizedPhones,
        AuthenticatedPrincipalInfo? ownerPrincipal,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            CarRecord? existing = null;
            await using (var selectCmd = conn.CreateCommand())
            {
                selectCmd.Transaction = tx;
                selectCmd.CommandText = """
                    SELECT car_id, car_public_key, key_fingerprint, owner_key_id, created_at_ms, updated_at_ms, last_register_ts_ms, last_seen_at_ms
                    FROM cars WHERE car_id = $carId;
                    """;
                selectCmd.Parameters.AddWithValue("$carId", carId);
                await using var r = await selectCmd.ExecuteReaderAsync(ct);
                if (await r.ReadAsync(ct))
                {
                    existing = new CarRecord(
                        r.GetString(0),
                        r.GetString(1),
                        r.GetString(2),
                        r.IsDBNull(3) ? null : r.GetInt32(3),
                        r.GetInt64(4),
                        r.GetInt64(5),
                        r.GetInt64(6),
                        r.GetInt64(7));
                }
            }

            if (existing != null)
            {
                // Strict TOFU pinning check
                if (!string.Equals(existing.KeyFingerprint, carKeyFingerprint, StringComparison.Ordinal))
                    return CarRegisterResultStatus.TofuKeyMismatch;

                if (ownerPrincipal != null && existing.OwnerKeyId.HasValue && existing.OwnerKeyId.Value != ownerPrincipal.OwnerKeyId)
                    return CarRegisterResultStatus.AccountForbidden;

                if (timestampMs < existing.LastRegisterTsMs)
                    return CarRegisterResultStatus.StaleTimestampReplay;

                if (ownerPrincipal != null && !existing.OwnerKeyId.HasValue)
                {
                    int ownedCount = await CountCarsForOwnerInternalAsync(conn, tx, ownerPrincipal.OwnerKeyId, ct);
                    if (ownedCount >= ownerPrincipal.MaxCars)
                        return CarRegisterResultStatus.AccountCarQuotaExceeded;
                }

                await using var updateCarCmd = conn.CreateCommand();
                updateCarCmd.Transaction = tx;
                updateCarCmd.CommandText = """
                    UPDATE cars
                    SET owner_key_id = COALESCE(owner_key_id, $ownerId),
                        updated_at_ms = $nowMs,
                        last_register_ts_ms = $tsMs,
                        last_seen_at_ms = $nowMs
                    WHERE car_id = $carId;
                    """;
                updateCarCmd.Parameters.AddWithValue("$ownerId", (object?)ownerPrincipal?.OwnerKeyId ?? DBNull.Value);
                updateCarCmd.Parameters.AddWithValue("$nowMs", nowMs);
                updateCarCmd.Parameters.AddWithValue("$tsMs", timestampMs);
                updateCarCmd.Parameters.AddWithValue("$carId", carId);
                await updateCarCmd.ExecuteNonQueryAsync(ct);
            }
            else
            {
                if (ownerPrincipal != null)
                {
                    int ownedCount = await CountCarsForOwnerInternalAsync(conn, tx, ownerPrincipal.OwnerKeyId, ct);
                    if (ownedCount >= ownerPrincipal.MaxCars)
                        return CarRegisterResultStatus.AccountCarQuotaExceeded;
                }

                await using var insertCarCmd = conn.CreateCommand();
                insertCarCmd.Transaction = tx;
                insertCarCmd.CommandText = """
                    INSERT INTO cars (car_id, car_public_key, key_fingerprint, owner_key_id, created_at_ms, updated_at_ms, last_register_ts_ms, last_seen_at_ms)
                    VALUES ($carId, $pubKey, $fp, $ownerId, $nowMs, $nowMs, $tsMs, $nowMs);
                    """;
                insertCarCmd.Parameters.AddWithValue("$carId", carId);
                insertCarCmd.Parameters.AddWithValue("$pubKey", carPublicKey);
                insertCarCmd.Parameters.AddWithValue("$fp", carKeyFingerprint);
                insertCarCmd.Parameters.AddWithValue("$ownerId", (object?)ownerPrincipal?.OwnerKeyId ?? DBNull.Value);
                insertCarCmd.Parameters.AddWithValue("$nowMs", nowMs);
                insertCarCmd.Parameters.AddWithValue("$tsMs", timestampMs);
                await insertCarCmd.ExecuteNonQueryAsync(ct);
            }

            // Track phones removed since previous trust list as explicitly revoked
            var oldPhones = new HashSet<string>(StringComparer.Ordinal);
            await using (var prevCmd = conn.CreateCommand())
            {
                prevCmd.Transaction = tx;
                prevCmd.CommandText = "SELECT phone_id FROM authorized_phones WHERE car_id = $carId;";
                prevCmd.Parameters.AddWithValue("$carId", carId);
                await using var r = await prevCmd.ExecuteReaderAsync(ct);
                while (await r.ReadAsync(ct))
                    oldPhones.Add(r.GetString(0));
            }

            var incomingSet = new HashSet<string>(authorizedPhones.Select(p => p.PhoneId), StringComparer.Ordinal);
            long revocationMarkerMs = Math.Max(nowMs, timestampMs);

            foreach (string removedPhoneId in oldPhones)
            {
                if (!incomingSet.Contains(removedPhoneId))
                {
                    await using var revCmd = conn.CreateCommand();
                    revCmd.Transaction = tx;
                    revCmd.CommandText = """
                        INSERT INTO revoked_phones (car_id, phone_id, revoked_at_ms)
                        VALUES ($carId, $phoneId, $revMs)
                        ON CONFLICT(car_id, phone_id) DO UPDATE SET revoked_at_ms = excluded.revoked_at_ms;
                        """;
                    revCmd.Parameters.AddWithValue("$carId", carId);
                    revCmd.Parameters.AddWithValue("$phoneId", removedPhoneId);
                    revCmd.Parameters.AddWithValue("$revMs", revocationMarkerMs);
                    await revCmd.ExecuteNonQueryAsync(ct);
                }
            }

            await using (var delPhones = conn.CreateCommand())
            {
                delPhones.Transaction = tx;
                delPhones.CommandText = "DELETE FROM authorized_phones WHERE car_id = $carId;";
                delPhones.Parameters.AddWithValue("$carId", carId);
                await delPhones.ExecuteNonQueryAsync(ct);
            }

            foreach (AuthorizedPhoneRecord p in authorizedPhones)
            {
                await using (var clearRev = conn.CreateCommand())
                {
                    clearRev.Transaction = tx;
                    clearRev.CommandText = "DELETE FROM revoked_phones WHERE car_id = $carId AND phone_id = $phoneId;";
                    clearRev.Parameters.AddWithValue("$carId", carId);
                    clearRev.Parameters.AddWithValue("$phoneId", p.PhoneId);
                    await clearRev.ExecuteNonQueryAsync(ct);
                }

                await using var insPhone = conn.CreateCommand();
                insPhone.Transaction = tx;
                insPhone.CommandText = """
                    INSERT INTO authorized_phones (car_id, phone_id, phone_name, platform, phone_public_key, key_fingerprint, paired_at_ms, car_grant_signature)
                    VALUES ($carId, $phoneId, $name, $platform, $pubKey, $fp, $pairedAt, $sig);
                    """;
                insPhone.Parameters.AddWithValue("$carId", carId);
                insPhone.Parameters.AddWithValue("$phoneId", p.PhoneId);
                insPhone.Parameters.AddWithValue("$name", (object?)p.PhoneName ?? DBNull.Value);
                insPhone.Parameters.AddWithValue("$platform", (object?)p.Platform ?? DBNull.Value);
                insPhone.Parameters.AddWithValue("$pubKey", p.PhonePublicKey);
                insPhone.Parameters.AddWithValue("$fp", p.KeyFingerprint);
                insPhone.Parameters.AddWithValue("$pairedAt", p.PairedAtMs);
                insPhone.Parameters.AddWithValue("$sig", p.CarGrantSignature);
                await insPhone.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return CarRegisterResultStatus.Success;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static async Task<int> CountCarsForOwnerInternalAsync(SqliteConnection conn, SqliteTransaction tx, int ownerKeyId, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT COUNT(*) FROM cars WHERE owner_key_id = $ownerId;";
        cmd.Parameters.AddWithValue("$ownerId", ownerKeyId);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
    }

    public async Task<AuthorizedPhoneRecord?> GetAuthorizedPhoneAsync(string carId, string phoneId, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT car_id, phone_id, phone_name, platform, phone_public_key, key_fingerprint, paired_at_ms, car_grant_signature
            FROM authorized_phones
            WHERE car_id = $carId AND phone_id = $phoneId;
            """;
        cmd.Parameters.AddWithValue("$carId", carId);
        cmd.Parameters.AddWithValue("$phoneId", phoneId);

        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct))
            return null;

        return new AuthorizedPhoneRecord(
            r.GetString(0),
            r.GetString(1),
            r.IsDBNull(2) ? null : r.GetString(2),
            r.IsDBNull(3) ? null : r.GetString(3),
            r.GetString(4),
            r.GetString(5),
            r.GetInt64(6),
            r.GetString(7));
    }

    /// <summary>
    /// Enrolls a newly Bluetooth-paired phone via its Car-signed PairingGrant before the car next syncs,
    /// provided it was paired at/after the car's last trust sync and was not explicitly revoked after pairedAtMs.
    /// </summary>
    public async Task<AuthorizedPhoneRecord?> TryEnrollPhoneViaPairingProofAsync(
        CarRecord car,
        string phoneId,
        string phonePublicKey,
        string phoneKeyFingerprint,
        long pairedAtMs,
        string carGrantSignature,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            // Check if already in authorized_phones
            await using (var existCmd = conn.CreateCommand())
            {
                existCmd.Transaction = tx;
                existCmd.CommandText = """
                    SELECT phone_public_key, key_fingerprint, paired_at_ms, car_grant_signature
                    FROM authorized_phones WHERE car_id = $carId AND phone_id = $phoneId;
                    """;
                existCmd.Parameters.AddWithValue("$carId", car.CarId);
                existCmd.Parameters.AddWithValue("$phoneId", phoneId);
                await using var r = await existCmd.ExecuteReaderAsync(ct);
                if (await r.ReadAsync(ct))
                {
                    string existingFp = r.GetString(1);
                    if (!string.Equals(existingFp, phoneKeyFingerprint, StringComparison.Ordinal))
                        return null;

                    return new AuthorizedPhoneRecord(
                        car.CarId, phoneId, null, null, r.GetString(0), existingFp, r.GetInt64(2), r.GetString(3));
                }
            }

            // Must not be revoked at or after pairedAtMs
            await using (var revCmd = conn.CreateCommand())
            {
                revCmd.Transaction = tx;
                revCmd.CommandText = "SELECT revoked_at_ms FROM revoked_phones WHERE car_id = $carId AND phone_id = $phoneId;";
                revCmd.Parameters.AddWithValue("$carId", car.CarId);
                revCmd.Parameters.AddWithValue("$phoneId", phoneId);
                object? revObj = await revCmd.ExecuteScalarAsync(ct);
                if (revObj is long revMs && revMs >= pairedAtMs)
                    return null;
            }

            // Must have been paired at or after the car's last register sync (both timestamps come from the car's clock)
            if (pairedAtMs < car.LastRegisterTsMs && pairedAtMs < car.UpdatedAtMs)
                return null;

            await using (var countCmd = conn.CreateCommand())
            {
                countCmd.Transaction = tx;
                countCmd.CommandText = "SELECT COUNT(*) FROM authorized_phones WHERE car_id = $carId;";
                countCmd.Parameters.AddWithValue("$carId", car.CarId);
                if (Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct)) >= 64)
                    return null;
            }

            await using (var insCmd = conn.CreateCommand())
            {
                insCmd.Transaction = tx;
                insCmd.CommandText = """
                    INSERT INTO authorized_phones (car_id, phone_id, phone_name, platform, phone_public_key, key_fingerprint, paired_at_ms, car_grant_signature)
                    VALUES ($carId, $phoneId, NULL, NULL, $pubKey, $fp, $pairedAt, $sig);
                    """;
                insCmd.Parameters.AddWithValue("$carId", car.CarId);
                insCmd.Parameters.AddWithValue("$phoneId", phoneId);
                insCmd.Parameters.AddWithValue("$pubKey", phonePublicKey);
                insCmd.Parameters.AddWithValue("$fp", phoneKeyFingerprint);
                insCmd.Parameters.AddWithValue("$pairedAt", pairedAtMs);
                insCmd.Parameters.AddWithValue("$sig", carGrantSignature);
                await insCmd.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return new AuthorizedPhoneRecord(car.CarId, phoneId, null, null, phonePublicKey, phoneKeyFingerprint, pairedAtMs, carGrantSignature);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<EnqueueCommandStatus> EnqueueCommandAsync(
        CommandEnvelopeDto envelope,
        long nowMs,
        int maxQueuedPerCar,
        CancellationToken ct = default)
    {
        string envelopeJson = JsonSerializer.Serialize(envelope, JsonOpts);
        int ttlSec = envelope.TtlSeconds ?? (int)Math.Max(1, (envelope.ExpiresAtMs - envelope.IssuedAtMs) / 1000);

        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            await SweepExpiredForCarInternalAsync(conn, tx, envelope.CarId, nowMs, ct);

            await using (var dupCmd = conn.CreateCommand())
            {
                dupCmd.Transaction = tx;
                dupCmd.CommandText = "SELECT 1 FROM commands WHERE command_id = $cmdId;";
                dupCmd.Parameters.AddWithValue("$cmdId", envelope.CommandId);
                if (await dupCmd.ExecuteScalarAsync(ct) != null)
                    return EnqueueCommandStatus.DuplicateCommandId;
            }

            await using (var countCmd = conn.CreateCommand())
            {
                countCmd.Transaction = tx;
                countCmd.CommandText = "SELECT COUNT(*) FROM commands WHERE car_id = $carId AND status = 'QUEUED';";
                countCmd.Parameters.AddWithValue("$carId", envelope.CarId);
                int activeQueued = Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct));
                if (activeQueued >= Math.Max(1, maxQueuedPerCar))
                    return EnqueueCommandStatus.QueueLimitReached;
            }

            await using (var insCmd = conn.CreateCommand())
            {
                insCmd.Transaction = tx;
                insCmd.CommandText = """
                    INSERT INTO commands (
                        command_id, car_id, phone_id, status, issued_at_ms, expires_at_ms, ttl_seconds,
                        executed_at_ms, message, envelope_json, created_at_ms
                    ) VALUES (
                        $cmdId, $carId, $phoneId, 'QUEUED', $issuedAt, $expiresAt, $ttl,
                        0, 'Waiting for car internet...', $envJson, $nowMs
                    );
                    """;
                insCmd.Parameters.AddWithValue("$cmdId", envelope.CommandId);
                insCmd.Parameters.AddWithValue("$carId", envelope.CarId);
                insCmd.Parameters.AddWithValue("$phoneId", envelope.PhoneId);
                insCmd.Parameters.AddWithValue("$issuedAt", envelope.IssuedAtMs);
                insCmd.Parameters.AddWithValue("$expiresAt", envelope.ExpiresAtMs);
                insCmd.Parameters.AddWithValue("$ttl", ttlSec);
                insCmd.Parameters.AddWithValue("$envJson", envelopeJson);
                insCmd.Parameters.AddWithValue("$nowMs", nowMs);
                await insCmd.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return EnqueueCommandStatus.Queued;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<(List<CommandStatusItemDto> Commands, EncryptedTelemetryDto? Telemetry)> GetPhoneCommandsAndTelemetryAsync(
        string carId,
        string phoneId,
        long nowMs,
        CancellationToken ct = default)
    {
        // Lazily expire overdue commands for this car first
        await SweepExpiredForCarAsync(carId, nowMs, ct);

        await using var conn = await OpenConnectionAsync(ct);

        var commands = new List<CommandStatusItemDto>();
        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                SELECT command_id, status, issued_at_ms, expires_at_ms, executed_at_ms, message
                FROM commands
                WHERE car_id = $carId AND phone_id = $phoneId
                ORDER BY issued_at_ms DESC, rowid DESC
                LIMIT 20;
                """;
            cmd.Parameters.AddWithValue("$carId", carId);
            cmd.Parameters.AddWithValue("$phoneId", phoneId);

            await using var r = await cmd.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
            {
                commands.Add(new CommandStatusItemDto
                {
                    CommandId = r.GetString(0),
                    Status = r.GetString(1),
                    IssuedAtMs = r.GetInt64(2),
                    ExpiresAtMs = r.GetInt64(3),
                    ExecutedAtMs = r.GetInt64(4),
                    Message = r.GetString(5)
                });
            }
        }

        EncryptedTelemetryDto? telemetry = null;
        await using (var telCmd = conn.CreateCommand())
        {
            telCmd.CommandText = """
                SELECT telemetry_json
                FROM telemetry_blobs
                WHERE car_id = $carId AND phone_id = $phoneId;
                """;
            telCmd.Parameters.AddWithValue("$carId", carId);
            telCmd.Parameters.AddWithValue("$phoneId", phoneId);
            object? rawJson = await telCmd.ExecuteScalarAsync(ct);
            if (rawJson is string s && !string.IsNullOrEmpty(s))
            {
                telemetry = JsonSerializer.Deserialize<EncryptedTelemetryDto>(s, JsonOpts);
            }
        }

        return (commands, telemetry);
    }

    public async Task<(CancelCommandOutcome Outcome, string ExistingStatus)> CancelCommandAtomicallyAsync(
        string commandId,
        string carId,
        long nowMs,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            string? status = null;
            long expiresAtMs = 0;
            await using (var sel = conn.CreateCommand())
            {
                sel.Transaction = tx;
                sel.CommandText = "SELECT status, expires_at_ms FROM commands WHERE command_id = $cmdId AND car_id = $carId;";
                sel.Parameters.AddWithValue("$cmdId", commandId);
                sel.Parameters.AddWithValue("$carId", carId);
                await using var r = await sel.ExecuteReaderAsync(ct);
                if (await r.ReadAsync(ct))
                {
                    status = r.GetString(0);
                    expiresAtMs = r.GetInt64(1);
                }
            }

            if (status == null)
                return (CancelCommandOutcome.NotFound, "");

            if (string.Equals(status, CommandStatuses.Canceled, StringComparison.Ordinal))
                return (CancelCommandOutcome.Canceled, CommandStatuses.Canceled);

            if (string.Equals(status, CommandStatuses.Queued, StringComparison.Ordinal))
            {
                if (nowMs >= expiresAtMs)
                {
                    await using var expCmd = conn.CreateCommand();
                    expCmd.Transaction = tx;
                    expCmd.CommandText = """
                        UPDATE commands
                        SET status = 'EXPIRED', message = 'Timed out after 5 minutes'
                        WHERE command_id = $cmdId;
                        """;
                    expCmd.Parameters.AddWithValue("$cmdId", commandId);
                    await expCmd.ExecuteNonQueryAsync(ct);
                    await tx.CommitAsync(ct);
                    return (CancelCommandOutcome.AlreadyTerminal, CommandStatuses.Expired);
                }

                await using var cancelCmd = conn.CreateCommand();
                cancelCmd.Transaction = tx;
                cancelCmd.CommandText = """
                    UPDATE commands
                    SET status = 'CANCELED', message = 'Canceled by phone'
                    WHERE command_id = $cmdId;
                    """;
                cancelCmd.Parameters.AddWithValue("$cmdId", commandId);
                await cancelCmd.ExecuteNonQueryAsync(ct);
                await tx.CommitAsync(ct);
                return (CancelCommandOutcome.Canceled, CommandStatuses.Canceled);
            }

            return (CancelCommandOutcome.AlreadyTerminal, status);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<bool> TryConsumePollNonceAndSaveTelemetryAsync(
        string carId,
        string nonce,
        long nowMs,
        Dictionary<string, EncryptedTelemetryDto>? telemetryMap,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            await using (var checkNonce = conn.CreateCommand())
            {
                checkNonce.Transaction = tx;
                checkNonce.CommandText = """
                    SELECT expires_at_ms FROM poll_nonces
                    WHERE car_id = $carId AND nonce = $nonce;
                    """;
                checkNonce.Parameters.AddWithValue("$carId", carId);
                checkNonce.Parameters.AddWithValue("$nonce", nonce);
                object? existingExp = await checkNonce.ExecuteScalarAsync(ct);
                if (existingExp is long expMs && expMs > nowMs)
                    return false;
            }

            await using (var upsertNonce = conn.CreateCommand())
            {
                upsertNonce.Transaction = tx;
                upsertNonce.CommandText = """
                    INSERT INTO poll_nonces (car_id, nonce, expires_at_ms)
                    VALUES ($carId, $nonce, $expMs)
                    ON CONFLICT(car_id, nonce) DO UPDATE SET expires_at_ms = excluded.expires_at_ms;
                    """;
                upsertNonce.Parameters.AddWithValue("$carId", carId);
                upsertNonce.Parameters.AddWithValue("$nonce", nonce);
                upsertNonce.Parameters.AddWithValue("$expMs", nowMs + ServerConstants.NonceWindowMs);
                await upsertNonce.ExecuteNonQueryAsync(ct);
            }

            await using (var touchCar = conn.CreateCommand())
            {
                touchCar.Transaction = tx;
                touchCar.CommandText = "UPDATE cars SET last_seen_at_ms = $nowMs WHERE car_id = $carId;";
                touchCar.Parameters.AddWithValue("$nowMs", nowMs);
                touchCar.Parameters.AddWithValue("$carId", carId);
                await touchCar.ExecuteNonQueryAsync(ct);
            }

            if (telemetryMap is { Count: > 0 })
            {
                foreach (var (phoneId, box) in telemetryMap)
                {
                    string json = JsonSerializer.Serialize(box, JsonOpts);
                    await using var upsertTel = conn.CreateCommand();
                    upsertTel.Transaction = tx;
                    upsertTel.CommandText = """
                        INSERT INTO telemetry_blobs (car_id, phone_id, telemetry_json, updated_at_ms)
                        VALUES ($carId, $phoneId, $json, $updatedAt)
                        ON CONFLICT(car_id, phone_id) DO UPDATE SET
                            telemetry_json = excluded.telemetry_json,
                            updated_at_ms = excluded.updated_at_ms;
                        """;
                    upsertTel.Parameters.AddWithValue("$carId", carId);
                    upsertTel.Parameters.AddWithValue("$phoneId", phoneId);
                    upsertTel.Parameters.AddWithValue("$json", json);
                    upsertTel.Parameters.AddWithValue("$updatedAt", box.UpdatedAtMs > 0 ? box.UpdatedAtMs : nowMs);
                    await upsertTel.ExecuteNonQueryAsync(ct);
                }
            }

            await SweepExpiredForCarInternalAsync(conn, tx, carId, nowMs, ct);
            await tx.CommitAsync(ct);
            return true;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<List<CommandEnvelopeDto>> FetchQueuedCommandsForCarAsync(string carId, long nowMs, CancellationToken ct = default)
    {
        await SweepExpiredForCarAsync(carId, nowMs, ct);

        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT envelope_json
            FROM commands
            WHERE car_id = $carId AND status = 'QUEUED' AND expires_at_ms > $nowMs
            ORDER BY issued_at_ms ASC, rowid ASC;
            """;
        cmd.Parameters.AddWithValue("$carId", carId);
        cmd.Parameters.AddWithValue("$nowMs", nowMs);

        var result = new List<CommandEnvelopeDto>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            string json = r.GetString(0);
            CommandEnvelopeDto? env = JsonSerializer.Deserialize<CommandEnvelopeDto>(json, JsonOpts);
            if (env != null)
                result.Add(env);
        }

        return result;
    }

    public async Task<bool> AcknowledgeCommandAsync(
        string commandId,
        string carId,
        bool ok,
        string message,
        long executedAtMs,
        long nowMs,
        CancellationToken ct = default)
    {
        string finalStatus = ok ? CommandStatuses.Executed : CommandStatuses.Failed;

        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            await using var upd = conn.CreateCommand();
            upd.Transaction = tx;
            upd.CommandText = """
                UPDATE commands
                SET status = $status,
                    executed_at_ms = $execAt,
                    message = $msg
                WHERE command_id = $cmdId AND car_id = $carId;
                """;
            upd.Parameters.AddWithValue("$status", finalStatus);
            upd.Parameters.AddWithValue("$execAt", executedAtMs);
            upd.Parameters.AddWithValue("$msg", message);
            upd.Parameters.AddWithValue("$cmdId", commandId);
            upd.Parameters.AddWithValue("$carId", carId);

            int rows = await upd.ExecuteNonQueryAsync(ct);
            if (rows == 0)
                return false;

            await using var touch = conn.CreateCommand();
            touch.Transaction = tx;
            touch.CommandText = "UPDATE cars SET last_seen_at_ms = $nowMs WHERE car_id = $carId;";
            touch.Parameters.AddWithValue("$nowMs", nowMs);
            touch.Parameters.AddWithValue("$carId", carId);
            await touch.ExecuteNonQueryAsync(ct);

            await tx.CommitAsync(ct);
            return true;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task SweepExpiredForCarAsync(string carId, long nowMs, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);
            await SweepExpiredForCarInternalAsync(conn, tx, carId, nowMs, ct);
            await tx.CommitAsync(ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static async Task SweepExpiredForCarInternalAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        string carId,
        long nowMs,
        CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE commands
            SET status = 'EXPIRED', message = 'Timed out after 5 minutes'
            WHERE car_id = $carId AND status = 'QUEUED' AND expires_at_ms <= $nowMs;
            """;
        cmd.Parameters.AddWithValue("$carId", carId);
        cmd.Parameters.AddWithValue("$nowMs", nowMs);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<(int ExpiredCount, int PrunedCommands, int PrunedNonces)> RunMaintenanceSweepAsync(long nowMs, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(ct);

            int expiredCount;
            await using (var expCmd = conn.CreateCommand())
            {
                expCmd.Transaction = tx;
                expCmd.CommandText = """
                    UPDATE commands
                    SET status = 'EXPIRED', message = 'Timed out after 5 minutes'
                    WHERE status = 'QUEUED' AND expires_at_ms <= $nowMs;
                    """;
                expCmd.Parameters.AddWithValue("$nowMs", nowMs);
                expiredCount = await expCmd.ExecuteNonQueryAsync(ct);
            }

            int prunedCommands;
            long commandCutoffMs = nowMs - ServerConstants.TerminalCommandRetentionMs;
            await using (var pruneCmd = conn.CreateCommand())
            {
                pruneCmd.Transaction = tx;
                pruneCmd.CommandText = """
                    DELETE FROM commands
                    WHERE status IN ('EXECUTED', 'FAILED', 'CANCELED', 'EXPIRED')
                      AND issued_at_ms < $cutoffMs
                      AND created_at_ms < $cutoffMs;
                    """;
                pruneCmd.Parameters.AddWithValue("$cutoffMs", commandCutoffMs);
                prunedCommands = await pruneCmd.ExecuteNonQueryAsync(ct);
            }

            int prunedNonces;
            // Nonces have expires_at_ms = created + 5m; deleting expires_at_ms < nowMs - 5m removes nonces older than 10 minutes
            long nonceCutoffMs = nowMs - (ServerConstants.NoncePruneAgeMs - ServerConstants.NonceWindowMs);
            await using (var pruneNonce = conn.CreateCommand())
            {
                pruneNonce.Transaction = tx;
                pruneNonce.CommandText = "DELETE FROM poll_nonces WHERE expires_at_ms < $nonceCutoff;";
                pruneNonce.Parameters.AddWithValue("$nonceCutoff", nonceCutoffMs);
                prunedNonces = await pruneNonce.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            return (expiredCount, prunedCommands, prunedNonces);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // -------------------------------------------------------------------------
    // Accounts & API Tokens (Multi-User Operator Mode)
    // -------------------------------------------------------------------------

    public async Task<(bool Created, AccountRecord? Account)> CreateAccountAsync(
        string username,
        byte[] passwordHash,
        byte[] passwordSalt,
        int iterations,
        int maxCars,
        long nowMs,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            try
            {
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT INTO accounts (username, password_hash, password_salt, hash_iterations, max_cars, token_version, is_disabled, created_at_ms)
                    VALUES ($user, $hash, $salt, $iter, $maxCars, 1, 0, $nowMs)
                    RETURNING id;
                    """;
                cmd.Parameters.AddWithValue("$user", username);
                cmd.Parameters.AddWithValue("$hash", passwordHash);
                cmd.Parameters.AddWithValue("$salt", passwordSalt);
                cmd.Parameters.AddWithValue("$iter", iterations);
                cmd.Parameters.AddWithValue("$maxCars", Math.Max(1, maxCars));
                cmd.Parameters.AddWithValue("$nowMs", nowMs);

                int id = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
                return (true, new AccountRecord(id, username, passwordHash, passwordSalt, iterations, Math.Max(1, maxCars), 1, false, nowMs));
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT
            {
                return (false, null);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<AccountRecord?> GetAccountByUsernameAsync(string username, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, username, password_hash, password_salt, hash_iterations, max_cars, token_version, is_disabled, created_at_ms
            FROM accounts WHERE username = $user;
            """;
        cmd.Parameters.AddWithValue("$user", username);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct))
            return null;

        return ReadAccountRecord(r);
    }

    public async Task<AccountRecord?> GetAccountByIdAsync(int id, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, username, password_hash, password_salt, hash_iterations, max_cars, token_version, is_disabled, created_at_ms
            FROM accounts WHERE id = $id;
            """;
        cmd.Parameters.AddWithValue("$id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct))
            return null;

        return ReadAccountRecord(r);
    }

    private static AccountRecord ReadAccountRecord(SqliteDataReader r) =>
        new(
            Id: r.GetInt32(0),
            Username: r.GetString(1),
            PasswordHash: (byte[])r[2],
            PasswordSalt: (byte[])r[3],
            HashIterations: r.GetInt32(4),
            MaxCars: r.GetInt32(5),
            TokenVersion: r.GetInt32(6),
            IsDisabled: r.GetInt32(7) != 0,
            CreatedAtMs: r.GetInt64(8));

    public async Task<(string PlainToken, ApiTokenRecord Record)> CreateApiTokenAsync(
        string label,
        int maxCars,
        long nowMs,
        int? accountId = null,
        CancellationToken ct = default)
    {
        var (plain, hashHex, prefix) = AccountTokenService.GenerateStaticApiToken();
        int safeMaxCars = Math.Max(1, maxCars);

        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO api_tokens (label, token_hash_hex, token_prefix, account_id, max_cars, is_revoked, created_at_ms, last_used_at_ms)
                VALUES ($label, $hash, $prefix, $acctId, $maxCars, 0, $nowMs, NULL)
                RETURNING id;
                """;
            cmd.Parameters.AddWithValue("$label", string.IsNullOrWhiteSpace(label) ? "API Token" : label.Trim());
            cmd.Parameters.AddWithValue("$hash", hashHex);
            cmd.Parameters.AddWithValue("$prefix", prefix);
            cmd.Parameters.AddWithValue("$acctId", (object?)accountId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$maxCars", safeMaxCars);
            cmd.Parameters.AddWithValue("$nowMs", nowMs);

            int id = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
            return (plain, new ApiTokenRecord(id, label, hashHex, prefix, accountId, safeMaxCars, false, nowMs, null));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<ApiTokenRecord?> ValidateAndTouchApiTokenAsync(string plainToken, long nowMs, CancellationToken ct = default)
    {
        string hashHex = AccountTokenService.HashApiToken(plainToken);
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, label, token_hash_hex, token_prefix, account_id, max_cars, is_revoked, created_at_ms, last_used_at_ms
            FROM api_tokens WHERE token_hash_hex = $hash;
            """;
        cmd.Parameters.AddWithValue("$hash", hashHex);

        ApiTokenRecord? rec = null;
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (await r.ReadAsync(ct))
            {
                rec = new ApiTokenRecord(
                    r.GetInt32(0),
                    r.GetString(1),
                    r.GetString(2),
                    r.GetString(3),
                    r.IsDBNull(4) ? null : r.GetInt32(4),
                    r.GetInt32(5),
                    r.GetInt32(6) != 0,
                    r.GetInt64(7),
                    r.IsDBNull(8) ? null : r.GetInt64(8));
            }
        }

        if (rec == null || rec.IsRevoked)
            return null;

        // Touch last_used_at_ms at most once per minute to avoid write churn on every poll
        if (!rec.LastUsedAtMs.HasValue || nowMs - rec.LastUsedAtMs.Value > 60_000)
        {
            await _writeLock.WaitAsync(ct);
            try
            {
                await using var upd = conn.CreateCommand();
                upd.CommandText = "UPDATE api_tokens SET last_used_at_ms = $nowMs WHERE id = $id;";
                upd.Parameters.AddWithValue("$nowMs", nowMs);
                upd.Parameters.AddWithValue("$id", rec.Id);
                await upd.ExecuteNonQueryAsync(ct);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        return rec;
    }

    public async Task<List<ApiTokenSummaryDto>> ListApiTokensAsync(CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, label, token_prefix, max_cars, is_revoked, created_at_ms, last_used_at_ms
            FROM api_tokens
            ORDER BY id DESC;
            """;
        var list = new List<ApiTokenSummaryDto>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new ApiTokenSummaryDto
            {
                Id = r.GetInt32(0),
                Label = r.GetString(1),
                TokenPrefix = r.GetString(2),
                MaxCars = r.GetInt32(3),
                IsRevoked = r.GetInt32(4) != 0,
                CreatedAtMs = r.GetInt64(5),
                LastUsedAtMs = r.IsDBNull(6) ? null : r.GetInt64(6)
            });
        }
        return list;
    }

    public async Task<bool> RevokeApiTokenAsync(int id, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await using var conn = await OpenConnectionAsync(ct);
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE api_tokens SET is_revoked = 1 WHERE id = $id;";
            cmd.Parameters.AddWithValue("$id", id);
            return await cmd.ExecuteNonQueryAsync(ct) > 0;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<(int RegisteredCars, int QueuedCommands)> GetDashboardCountsAsync(long nowMs, CancellationToken ct = default)
    {
        await using var conn = await OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT
                (SELECT COUNT(*) FROM cars),
                (SELECT COUNT(*) FROM commands WHERE status = 'QUEUED' AND expires_at_ms > $nowMs);
            """;
        cmd.Parameters.AddWithValue("$nowMs", nowMs);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (await r.ReadAsync(ct))
            return (r.GetInt32(0), r.GetInt32(1));
        return (0, 0);
    }

    public void Dispose()
    {
        _writeLock.Dispose();
    }
}
