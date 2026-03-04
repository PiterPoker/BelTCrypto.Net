namespace BelTCrypto.Core.Interfaces;

public interface IDecryptor
{
    void Decrypt(ReadOnlySpan<byte> input, Span<byte> output);
}
