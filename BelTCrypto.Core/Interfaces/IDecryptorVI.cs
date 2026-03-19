namespace BelTCrypto.Core.Interfaces;

public interface IDecryptorVI
{
    void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x);

}
