namespace BelTCrypto.Core.Interfaces;

public interface IEncryptor
{
    public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
}
