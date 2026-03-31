namespace BelTCrypto.Core.Interfaces;

public interface IBelTKeyService
{
    void Expand(ReadOnlySpan<byte> sourceKey, Span<byte> expandedKey);
    void Rep(ReadOnlySpan<byte> x, ReadOnlySpan<byte> d, ReadOnlySpan<byte> i, int mBits, Span<byte> y);
}
