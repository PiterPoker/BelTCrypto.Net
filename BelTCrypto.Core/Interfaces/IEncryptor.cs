namespace BelTCrypto.Core.Interfaces;

public interface IEncryptor
{
    void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, Span<byte> y) => throw new NotImplementedException();
}
