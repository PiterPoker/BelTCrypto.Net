using System.Security.Cryptography;

namespace BelTCrypto.Net;

public class KeyQuotaExceededException : CryptographicException
{
    public Guid KeyId { get; }
    public BelTEncryptionMode Mode { get; }

    public KeyQuotaExceededException(Guid keyId, BelTEncryptionMode mode, string message)
        : base(message)
    {
        KeyId = keyId;
        Mode = mode;
    }
}
