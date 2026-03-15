using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal sealed class BelTCbcDecryptTransform : BelTCbcTransform
{
    public BelTCbcDecryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> s)
        : base(block, s)
    {
    }

    public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int totalProcessed = 0;
        int currentOffset = inputOffset;
        int remaining = inputCount;

        if (_bufferCount == 16 && remaining > 0)
        {
            DecryptStandardBlock(_buffer, outputBuffer.AsSpan(outputOffset + totalProcessed, 16));
            totalProcessed += 16;
            _bufferCount = 0;
        }

        while (remaining > 16)
        {
            DecryptStandardBlock(inputBuffer.AsSpan(currentOffset, 16), outputBuffer.AsSpan(outputOffset + totalProcessed, 16));
            currentOffset += 16;
            remaining -= 16;
            totalProcessed += 16;
        }

        if (remaining > 0)
        {
            Array.Copy(inputBuffer, currentOffset, _buffer, _bufferCount, remaining);
            _bufferCount += remaining;
        }

        return totalProcessed;
    }

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] finalY = new byte[_bufferCount + inputCount];
        Array.Copy(_buffer, 0, finalY, 0, _bufferCount);
        Array.Copy(inputBuffer, inputOffset, finalY, _bufferCount, inputCount);

        if (finalY.Length == 0) return [];
        if (finalY.Length < 16) throw new CryptographicException("CTS требует минимум 128 бит данных.");

        int totalLen = finalY.Length;
        int n = (totalLen + 15) / 16;
        int m = totalLen % 16;
        byte[] finalX = new byte[totalLen];

        if (m == 0)
        {
            for (int i = 0; i < n; i++)
            {
                DecryptStandardBlock(finalY.AsSpan(i * 16, 16), finalX.AsSpan(i * 16, 16));
            }
        }
        else
        {
            // 4.1 Расшифрование блоков Y1...Yn-2
            for (int i = 0; i < n - 2; i++)
            {
                DecryptStandardBlock(finalY.AsSpan(i * 16, 16), finalX.AsSpan(i * 16, 16));
            }

            // 4.2 Расшифровываем Yn-1 (предпоследний блок шифртекста)
            Span<byte> ynMinus1 = finalY.AsSpan((n - 2) * 16, 16);
            Span<byte> W = stackalloc byte[16];
            _block.Decrypt(ynMinus1, W); // W = (Xn ⊕ Yn) || r

            // 4.3 Восстанавливаем блок для расшифрования Xn-1
            // Нам нужно создать блок (Yn || r)
            Span<byte> Yn_r = stackalloc byte[16];
            finalY.AsSpan((n - 1) * 16, m).CopyTo(Yn_r); // Копируем Yn (m байт)
            W[m..].CopyTo(Yn_r[m..]);                    // Дописываем r (16-m байт) из W

            // 4.4 Получаем Xn
            // По формуле: Xn = [W]m ⊕ [Yn_r]m (XOR первых m байт)
            Span<byte> xn = finalX.AsSpan((n - 1) * 16, m);
            for (int i = 0; i < m; i++)
            {
                xn[i] = (byte)(W[i] ^ Yn_r[i]);
            }

            // 4.5 Получаем Xn-1
            // Расшифровываем восстановленный блок Yn_r
            Span<byte> decryptedYn_r = stackalloc byte[16];
            _block.Decrypt(Yn_r, decryptedYn_r);

            // И делаем XOR с Yn-2 (который сейчас лежит в _prevY)
            Xor(decryptedYn_r, _prevY, finalX.AsSpan((n - 2) * 16, 16));
        }

        return finalX;
    }

    private void DecryptStandardBlock(ReadOnlySpan<byte> y, Span<byte> x)
    {
        _block.Decrypt(y, x);
        Xor(x, _prevY, x);
        y.CopyTo(_prevY);
    }
}