using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DigitalConnectPlus.Server.Crypto;

/// <summary>
/// Byte-exact NIST P-256 (secp256r1 / prime256v1) SPKI DER &amp; ASN.1 DER SHA256withECDSA
/// cryptographic primitives matching Gen5W Digital Control Android/iOS/Car clients.
/// </summary>
public static partial class Gen5WCrypto
{
    private const string NistP256Oid = "1.2.840.10045.3.1.7";

    [GeneratedRegex("^car_[0-9a-f]{16,40}$", RegexOptions.CultureInvariant)]
    public static partial Regex CarIdRegex();

    [GeneratedRegex("^ph_[0-9a-f]{12,40}$", RegexOptions.CultureInvariant)]
    public static partial Regex PhoneIdRegex();

    [GeneratedRegex("^cmd_[0-9a-f]{24,40}$", RegexOptions.CultureInvariant)]
    public static partial Regex CommandIdRegex();

    [GeneratedRegex("^[A-Za-z0-9._-]{8,128}$", RegexOptions.CultureInvariant)]
    public static partial Regex NonceRegex();

    public static bool IsValidCarId(string? id) => !string.IsNullOrEmpty(id) && CarIdRegex().IsMatch(id);
    public static bool IsValidPhoneId(string? id) => !string.IsNullOrEmpty(id) && PhoneIdRegex().IsMatch(id);
    public static bool IsValidCommandId(string? id) => !string.IsNullOrEmpty(id) && CommandIdRegex().IsMatch(id);
    public static bool IsValidNonce(string? nonce) => !string.IsNullOrEmpty(nonce) && NonceRegex().IsMatch(nonce);

    public static string Sha256HexBytes(ReadOnlySpan<byte> bytes)
    {
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(bytes, digest);
        return Convert.ToHexStringLower(digest);
    }

    public static string Sha256HexUtf8(string text)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(text ?? "");
        return Sha256HexBytes(utf8);
    }

    /// <summary>
    /// Validates Base64-encoded X.509 SubjectPublicKeyInfo (SPKI) DER for NIST P-256 (secp256r1 / prime256v1)
    /// and returns its 64-character lowercase SHA-256 hex fingerprint over the decoded DER bytes.
    /// </summary>
    public static bool TryDeriveKeyFingerprintHex(string? spkiBase64, out string fingerprintHex)
    {
        fingerprintHex = "";
        if (!TryImportP256SpkiPublicKey(spkiBase64, out ECDsa? ecdsa, out byte[] derBytes))
            return false;

        using (ecdsa)
        {
            fingerprintHex = Sha256HexBytes(derBytes);
            return true;
        }
    }

    public static string DeriveKeyFingerprintHexOrThrow(string spkiBase64)
    {
        if (!TryDeriveKeyFingerprintHex(spkiBase64, out string fp))
            throw new FormatException("Invalid NIST P-256 SPKI DER Base64 public key.");
        return fp;
    }

    public static bool IsValidP256SpkiBase64(string? spkiBase64)
    {
        if (!TryImportP256SpkiPublicKey(spkiBase64, out ECDsa? ecdsa, out _))
            return false;

        ecdsa?.Dispose();
        return true;
    }

    public static bool TryImportP256SpkiPublicKey(string? spkiBase64, out ECDsa? ecdsa, out byte[] derBytes)
    {
        ecdsa = null;
        derBytes = [];

        if (string.IsNullOrWhiteSpace(spkiBase64) || spkiBase64.Length > 256)
            return false;

        // Reject whitespace or line wraps in Base64
        for (int i = 0; i < spkiBase64.Length; i++)
        {
            char c = spkiBase64[i];
            if (char.IsWhiteSpace(c))
                return false;
        }

        try
        {
            derBytes = Convert.FromBase64String(spkiBase64);
        }
        catch
        {
            return false;
        }

        // Standard uncompressed P-256 SPKI DER is 91 bytes; allow 80..120 per protocol reference
        if (derBytes.Length is < 80 or > 120)
            return false;

        ECDsa? candidate = null;
        try
        {
            candidate = ECDsa.Create();
            candidate.ImportSubjectPublicKeyInfo(derBytes, out int bytesRead);
            if (bytesRead != derBytes.Length || candidate.KeySize != 256)
            {
                candidate.Dispose();
                return false;
            }

            ECParameters ecParams = candidate.ExportParameters(includePrivateParameters: false);
            string? oid = ecParams.Curve.Oid?.Value;
            string? friendly = ecParams.Curve.Oid?.FriendlyName;

            bool isP256 =
                string.Equals(oid, NistP256Oid, StringComparison.Ordinal) ||
                string.Equals(friendly, "nistP256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(friendly, "ECDSA_P256", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(friendly, "prime256v1", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(friendly, "secp256r1", StringComparison.OrdinalIgnoreCase);

            if (!isP256 || ecParams.Q.X is not { Length: 32 } || ecParams.Q.Y is not { Length: 32 })
            {
                candidate.Dispose();
                return false;
            }

            ecdsa = candidate;
            return true;
        }
        catch
        {
            candidate?.Dispose();
            return false;
        }
    }

    /// <summary>
    /// Verifies an RFC 4648 Base64 ASN.1 DER SHA256withECDSA signature (Rfc3279DerSequence)
    /// over the exact UTF-8 bytes of <paramref name="canonicalString"/>.
    /// </summary>
    public static bool VerifyEcdsaP256DerBase64(string? spkiBase64, string canonicalString, string? sigDerBase64)
    {
        if (string.IsNullOrWhiteSpace(sigDerBase64) || sigDerBase64.Length > 256)
            return false;

        for (int i = 0; i < sigDerBase64.Length; i++)
        {
            if (char.IsWhiteSpace(sigDerBase64[i]))
                return false;
        }

        byte[] sigDer;
        try
        {
            sigDer = Convert.FromBase64String(sigDerBase64);
        }
        catch
        {
            return false;
        }

        // ASN.1 DER SEQUENCE { r INTEGER, s INTEGER } for P-256 is 64..74 bytes (starts with 0x30)
        if (sigDer.Length is < 8 or > 96 || sigDer[0] != 0x30)
            return false;

        if (!TryImportP256SpkiPublicKey(spkiBase64, out ECDsa? pubKey, out _) || pubKey is null)
            return false;

        using (pubKey)
        {
            try
            {
                byte[] utf8 = Encoding.UTF8.GetBytes(canonicalString);
                return pubKey.VerifyData(
                    utf8,
                    sigDer,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence);
            }
            catch
            {
                return false;
            }
        }
    }

    public static string SignEcdsaP256DerBase64(ECDsa privateKey, string canonicalString)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(canonicalString);
        byte[] derSig = privateKey.SignData(utf8, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        return Convert.ToBase64String(derSig);
    }

    public static string ExportSpkiBase64(ECDsa key)
    {
        byte[] spkiDer = key.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(spkiDer);
    }

    public static bool IsValidStrictBase64(string? b64, int minDecodedBytes, int maxDecodedBytes)
    {
        if (string.IsNullOrEmpty(b64))
            return false;

        for (int i = 0; i < b64.Length; i++)
        {
            if (char.IsWhiteSpace(b64[i]))
                return false;
        }

        try
        {
            byte[] decoded = Convert.FromBase64String(b64);
            return decoded.Length >= minDecodedBytes && decoded.Length <= maxDecodedBytes;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Computes boxDigestHex = sha256HexUtf8("${ephemeralPubKey}.${iv}.${ciphertext}.${mac}")
    /// </summary>
    public static string ComputeBoxDigestHex(string ephemeralPubKey, string iv, string ciphertext, string mac)
    {
        string joined = $"{ephemeralPubKey}.{iv}.{ciphertext}.{mac}";
        return Sha256HexUtf8(joined);
    }

    // -------------------------------------------------------------------------
    // Exact Canonical Signing Strings (7 Signatures Total — no trailing newline)
    // -------------------------------------------------------------------------

    // #1 Car Registration
    public static string BuildCarRegisterCanonical(string carId, string carPublicKeyFingerprintHex, long timestampMs) =>
        $"GEN5W-CAR-REG-V1|{carId}|{carPublicKeyFingerprintHex}|{timestampMs}";

    // #2 Car Pairing Grant
    public static string BuildPairingGrantCanonical(string carId, string phoneId, string phonePublicKeyFingerprintHex, long pairedAtMs) =>
        $"GEN5W-GRANT-V1|{carId}|{phoneId}|{phonePublicKeyFingerprintHex}|{pairedAtMs}";

    // #3 Command Submission
    public static string BuildCommandEnvelopeCanonical(
        string commandId,
        string carId,
        string phoneId,
        long issuedAtMs,
        long expiresAtMs,
        string boxDigestHex) =>
        $"GEN5W-ENV-V1|{commandId}|{carId}|{phoneId}|{issuedAtMs}|{expiresAtMs}|{boxDigestHex}";

    // #4 Phone Status Poll
    public static string BuildPhoneStatusCanonical(string carId, string phoneId, long ts) =>
        $"GEN5W-STATUS-V1|{carId}|{phoneId}|{ts}";

    // #5 Phone Cancel Command
    public static string BuildPhoneCancelCanonical(string commandId, string carId, string phoneId, long ts) =>
        $"GEN5W-CANCEL-V1|{commandId}|{carId}|{phoneId}|{ts}";

    // #6 Car Long-Poll
    public static string BuildCarPollCanonical(string carId, long timestampMs, string nonce) =>
        $"GEN5W-POLL-V1|{carId}|{timestampMs}|{nonce}";

    // #7 Car Execution Receipt
    public static string BuildCarAckCanonical(string commandId, string carId, bool ok, long executedAtMs, string message) =>
        $"GEN5W-ACK-V1|{commandId}|{carId}|{(ok ? "1" : "0")}|{executedAtMs}|{Sha256HexUtf8(message ?? "")}";

    public static bool IsWithinClockSkew(long clientTimestampMs, long serverNowMs, long toleranceMs = Configuration.ServerConstants.DefaultClockSkewMs)
    {
        long diff = clientTimestampMs >= serverNowMs
            ? clientTimestampMs - serverNowMs
            : serverNowMs - clientTimestampMs;
        return diff <= toleranceMs;
    }
}
