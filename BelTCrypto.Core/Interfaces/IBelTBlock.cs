namespace BelTCrypto.Core.Interfaces;

public interface IBelTBlock : IEncryptor, IDecryptor, IDisposable
{
    void ResetKey(ReadOnlySpan<byte> newKey);
}
