namespace BelTCrypto.Core.Interfaces;

public interface IEncryptor
{
    void Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
}
