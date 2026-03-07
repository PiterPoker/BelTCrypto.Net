using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal sealed class BelTEcbDecryptTransform(IBelTBlock block) : BelTEcbTransform(block)
{
    protected override void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output) => _block.Decrypt(input, output);

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] finalY = new byte[_bufferCount + inputCount];
        Array.Copy(_buffer, 0, finalY, 0, _bufferCount);
        Array.Copy(inputBuffer, inputOffset, finalY, _bufferCount, inputCount);

        if (finalY.Length == 0) return [];

        int totalLen = finalY.Length;
        int n = (totalLen + 15) / 16;
        int m = totalLen % 16;
        byte[] finalX = new byte[totalLen];

        if (m == 0) // Шаг 2
        {
            for (int i = 0; i < n; i++)
                _block.Decrypt(finalY.AsSpan(i * 16, 16), finalX.AsSpan(i * 16, 16));
        }
        else // Шаг 3 (CTS)
        {
            for (int i = 0; i < n - 2; i++)
                _block.Decrypt(finalY.AsSpan(i * 16, 16), finalX.AsSpan(i * 16, 16));

            // 3.2 (Xn || r) <- belt-block-1(Yn-1, K)
            Span<byte> xn_r = stackalloc byte[16];
            _block.Decrypt(finalY.AsSpan((n - 2) * 16, 16), xn_r);

            xn_r[..m].CopyTo(finalX.AsSpan((n - 1) * 16, m)); // Xn
            var r = xn_r[m..];

            // 3.3 Xn-1 <- belt-block-1(Yn || r, K)
            Span<byte> yn_r = stackalloc byte[16];
            finalY[((n - 1) * 16)..].CopyTo(yn_r); // Yn
            r.CopyTo(yn_r[m..]); // r

            _block.Decrypt(yn_r, finalX.AsSpan((n - 2) * 16, 16)); // Xn-1
        }
        return finalX;
    }
}
