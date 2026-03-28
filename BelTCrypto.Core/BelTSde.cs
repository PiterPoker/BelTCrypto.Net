using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTSde : IBelTSde
{
    private readonly IBelTBlock _block;

    public BelTSde(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }
    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x)
    {
        throw new NotImplementedException();
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y)
    {
        throw new NotImplementedException();
    }
}
