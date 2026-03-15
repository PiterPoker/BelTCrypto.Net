namespace BelTCrypto.Core.Interfaces;

public interface IDecryptor
{
    [Obsolete]
    void Decrypt(ReadOnlySpan<byte> input, Span<byte> output) => throw new NotImplementedException();
    void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, Span<byte> x) => throw new NotImplementedException();

}
