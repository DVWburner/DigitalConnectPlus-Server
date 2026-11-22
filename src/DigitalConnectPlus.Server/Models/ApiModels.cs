using System.Text.Json.Serialization;

namespace DigitalConnectPlus.Server.Models;

public static class CommandStatuses
{
    public const string Queued = "QUEUED";
    public const string Executed = "EXECUTED";
    public const string Failed = "FAILED";
    public const string Canceled = "CANCELED";
    public const string Expired = "EXPIRED";
}

public sealed class ApiErrorResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = false;

    [JsonPropertyName("error")]
    public required string Error { get; init; }
}

public sealed class HealthResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("service")]
    public required string Service { get; init; }

    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("timeMs")]
    public required long TimeMs { get; init; }
}

// -----------------------------------------------------------------------------
// 2. POST /api/v1/cars/register
// -----------------------------------------------------------------------------

public sealed class AuthorizedPhoneDto
{
    [JsonPropertyName("phoneId")]
    public string PhoneId { get; set; } = "";

    [JsonPropertyName("phoneName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PhoneName { get; set; }

    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; set; }

    [JsonPropertyName("phonePublicKey")]
    public string PhonePublicKey { get; set; } = "";

    [JsonPropertyName("pairedAtMs")]
    public long PairedAtMs { get; set; }

    [JsonPropertyName("carGrantSignature")]
    public string CarGrantSignature { get; set; } = "";
}

public sealed class CarRegisterRequest
{
    [JsonPropertyName("carId")]
    public string CarId { get; set; } = "";

    [JsonPropertyName("carPublicKey")]
    public string CarPublicKey { get; set; } = "";

    [JsonPropertyName("timestampMs")]
    public long TimestampMs { get; set; }

    [JsonPropertyName("carSignature")]
    public string CarSignature { get; set; } = "";

    [JsonPropertyName("authorizedPhones")]
    public List<AuthorizedPhoneDto>? AuthorizedPhones { get; set; }
}

public sealed class CarRegisterResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("carId")]
    public required string CarId { get; init; }

    [JsonPropertyName("authorizedPhoneCount")]
    public required int AuthorizedPhoneCount { get; init; }
}

// -----------------------------------------------------------------------------
// 3. POST /api/v1/commands & Command Envelope
// -----------------------------------------------------------------------------

public sealed class E2eeBoxDto
{
    [JsonPropertyName("ephemeralPubKey")]
    public string EphemeralPubKey { get; set; } = "";

    [JsonPropertyName("iv")]
    public string Iv { get; set; } = "";

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = "";

    [JsonPropertyName("mac")]
    public string Mac { get; set; } = "";
}

public sealed class PairingProofDto
{
    [JsonPropertyName("phonePublicKey")]
    public string PhonePublicKey { get; set; } = "";

    [JsonPropertyName("pairedAtMs")]
    public long PairedAtMs { get; set; }

    [JsonPropertyName("carGrantSignature")]
    public string CarGrantSignature { get; set; } = "";
}

public sealed class CommandEnvelopeDto
{
    [JsonPropertyName("commandId")]
    public string CommandId { get; set; } = "";

    [JsonPropertyName("carId")]
    public string CarId { get; set; } = "";

    [JsonPropertyName("phoneId")]
    public string PhoneId { get; set; } = "";

    [JsonPropertyName("issuedAtMs")]
    public long IssuedAtMs { get; set; }

    [JsonPropertyName("expiresAtMs")]
    public long ExpiresAtMs { get; set; }

    [JsonPropertyName("ttlSeconds")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? TtlSeconds { get; set; }

    [JsonPropertyName("e2ee")]
    public E2eeBoxDto? E2ee { get; set; }

    [JsonPropertyName("phoneSignature")]
    public string PhoneSignature { get; set; } = "";

    [JsonPropertyName("pairingProof")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PairingProofDto? PairingProof { get; set; }

    [JsonPropertyName("clientHint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientHint { get; set; }
}

public sealed class CommandSubmitResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("commandId")]
    public required string CommandId { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("expiresAtMs")]
    public required long ExpiresAtMs { get; init; }
}

// -----------------------------------------------------------------------------
// 4. GET /api/v1/commands & 5. DELETE /api/v1/commands/:commandId
// -----------------------------------------------------------------------------

public sealed class EncryptedTelemetryDto
{
    [JsonPropertyName("ephemeralPubKey")]
    public string EphemeralPubKey { get; set; } = "";

    [JsonPropertyName("iv")]
    public string Iv { get; set; } = "";

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = "";

    [JsonPropertyName("mac")]
    public string Mac { get; set; } = "";

    [JsonPropertyName("updatedAtMs")]
    public long UpdatedAtMs { get; set; }
}

public sealed class CommandStatusItemDto
{
    [JsonPropertyName("commandId")]
    public required string CommandId { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }

    [JsonPropertyName("issuedAtMs")]
    public required long IssuedAtMs { get; init; }

    [JsonPropertyName("expiresAtMs")]
    public required long ExpiresAtMs { get; init; }

    [JsonPropertyName("executedAtMs")]
    public required long ExecutedAtMs { get; init; }

    [JsonPropertyName("message")]
    public required string Message { get; init; }
}

public sealed class PhoneCommandsStatusResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("commands")]
    public required List<CommandStatusItemDto> Commands { get; init; }

    [JsonPropertyName("encryptedTelemetry")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public EncryptedTelemetryDto? EncryptedTelemetry { get; init; }
}

public sealed class CommandCancelResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("commandId")]
    public required string CommandId { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }
}

// -----------------------------------------------------------------------------
// 6. POST /api/v1/car/poll & 7. POST /api/v1/car/ack
// -----------------------------------------------------------------------------

public sealed class CarPollRequest
{
    [JsonPropertyName("carId")]
    public string CarId { get; set; } = "";

    [JsonPropertyName("timestampMs")]
    public long TimestampMs { get; set; }

    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = "";

    [JsonPropertyName("waitSeconds")]
    public int? WaitSeconds { get; set; }

    [JsonPropertyName("carSignature")]
    public string CarSignature { get; set; } = "";

    [JsonPropertyName("encryptedTelemetry")]
    public Dictionary<string, EncryptedTelemetryDto>? EncryptedTelemetry { get; set; }
}

public sealed class CarPollResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("commands")]
    public required List<CommandEnvelopeDto> Commands { get; init; }
}

public sealed class CarAckRequest
{
    [JsonPropertyName("commandId")]
    public string CommandId { get; set; } = "";

    [JsonPropertyName("carId")]
    public string CarId { get; set; } = "";

    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("executedAtMs")]
    public long ExecutedAtMs { get; set; }

    [JsonPropertyName("carSignature")]
    public string CarSignature { get; set; } = "";
}

public sealed class CarAckResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; } = true;

    [JsonPropertyName("commandId")]
    public required string CommandId { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }
}

// -----------------------------------------------------------------------------
// Multi-User Account Auth (/api/v1/auth/* — market.ioniqthemes.com compatible)
// -----------------------------------------------------------------------------

public sealed class AccountCredentialsRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("password")]
    public string? Password { get; set; }
}

public sealed class AccountProfileDto
{
    [JsonPropertyName("username")]
    public required string Username { get; init; }

    [JsonPropertyName("createdAt")]
    public required string CreatedAt { get; init; }
}

public sealed class AuthActionResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    [JsonPropertyName("message")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; init; }

    [JsonPropertyName("error")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Error { get; init; }

    [JsonPropertyName("token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Token { get; init; }

    [JsonPropertyName("tokenType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenType { get; init; }

    [JsonPropertyName("expiresAt")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExpiresAt { get; init; }

    [JsonPropertyName("account")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AccountProfileDto? Account { get; init; }
}

// -----------------------------------------------------------------------------
// Admin IPC DTOs (Service <-> Tray App)
// -----------------------------------------------------------------------------

public sealed class ServerLiveStatusDto
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

public sealed class ApiTokenSummaryDto
{
    public int Id { get; set; }
    public string Label { get; set; } = "";
    public string TokenPrefix { get; set; } = "";
    public int MaxCars { get; set; }
    public bool IsRevoked { get; set; }
    public long CreatedAtMs { get; set; }
    public long? LastUsedAtMs { get; set; }
}
