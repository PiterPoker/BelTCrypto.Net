namespace BelTCrypto.Core.Interfaces.Old;

[Obsolete]
public interface IBelTBlockOld : IEncryptor, IDecryptor, IDisposable
{
    void ResetKey(ReadOnlySpan<byte> newKey);
}
