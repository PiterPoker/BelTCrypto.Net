namespace BelTCrypto.Core.Interfaces;

public interface ICompressor
{
    (byte[] S, byte[] Y) Compress(ReadOnlySpan<byte> x);
}
