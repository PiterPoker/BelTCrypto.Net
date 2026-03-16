namespace BelTCrypto.Core.Interfaces;

public interface IEncryptorVI
{
    void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y);
}
