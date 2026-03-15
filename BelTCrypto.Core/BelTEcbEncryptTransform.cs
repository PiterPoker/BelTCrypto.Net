using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal sealed class BelTEcbEncryptTransform(IBelTBlockOld block) : BelTEcbTransform(block)
{
    protected override void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output) => _block.Encrypt(input, output);

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] finalX = new byte[_bufferCount + inputCount];
        Array.Copy(_buffer, 0, finalX, 0, _bufferCount);
        Array.Copy(inputBuffer, inputOffset, finalX, _bufferCount, inputCount);

        if (finalX.Length == 0) return Array.Empty<byte>();
        if (finalX.Length < 16) throw new CryptographicException("belt-ecb требует длину сообщения не менее 128 бит.");

        int totalLen = finalX.Length;
        int n = (totalLen + 15) / 16;
        int m = totalLen % 16;
        byte[] finalY = new byte[totalLen];

        if (m == 0) // Шаг 2 стандарта
        {
            for (int i = 0; i < n; i++)
                _block.Encrypt(finalX.AsSpan(i * 16, 16), finalY.AsSpan(i * 16, 16));
        }
        else // Шаг 3 стандарта (CTS)
        {
            // 3.1 блоки 1..n-2
            for (int i = 0; i < n - 2; i++)
                _block.Encrypt(finalX.AsSpan(i * 16, 16), finalY.AsSpan(i * 16, 16));

            // 3.2 (Yn || r) <- belt-block(Xn-1, K)
            Span<byte> tempYn_r = stackalloc byte[16];
            _block.Encrypt(finalX.AsSpan((n - 2) * 16, 16), tempYn_r);

            tempYn_r[..m].CopyTo(finalY.AsSpan((n - 1) * 16, m)); // Yn
            var r = tempYn_r[m..];

            // 3.3 Yn-1 <- belt-block(Xn || r, K)
            Span<byte> xn_r = stackalloc byte[16];
            finalX[((n - 1) * 16)..].CopyTo(xn_r); // Xn
            r.CopyTo(xn_r[m..]); // r

            _block.Encrypt(xn_r, finalY.AsSpan((n - 2) * 16, 16)); // Yn-1
        }
        return finalY;
    }
}