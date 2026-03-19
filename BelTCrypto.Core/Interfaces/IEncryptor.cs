namespace BelTCrypto.Core.Interfaces;

public interface IEncryptor
{
    [Obsolete]
    public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output) => throw new NotImplementedException();
    void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, Span<byte> y) => throw new NotImplementedException();
}
