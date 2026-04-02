namespace BelTCrypto.Core.Interfaces;

public interface IDecryptor
{
    void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, Span<byte> x) => throw new NotImplementedException();

}
