using System.Security.Cryptography;
using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces.Old;

namespace BelTCrypto.Core;

internal sealed class BelTCbcEncryptTransform : BelTCbcTransform
{

    public BelTCbcEncryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> s)
        : base(block, s)
    {
    }

    // Этот метод обрабатывает только полные блоки, которые ТОЧНО не последние
    public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int totalProcessed = 0;
        int currentOffset = inputOffset;
        int remaining = inputCount;

        // 1. Если в буфере что-то было, и пришли новые данные
        if (_bufferCount > 0 && remaining > 0)
        {
            // Если у нас уже есть полный блок в буфере И пришли новые данные,
            // значит блок в буфере точно можно шифровать (он не последний)
            if (_bufferCount == 16)
            {
                EncryptStandardBlock(_buffer, outputBuffer.AsSpan(outputOffset + totalProcessed, 16));
                totalProcessed += 16;
                _bufferCount = 0;
            }
        }

        // 2. Обрабатываем входящие данные, оставляя последние 1..16 байт в буфере
        while (remaining > 16)
        {
            EncryptStandardBlock(inputBuffer.AsSpan(currentOffset, 16), outputBuffer.AsSpan(outputOffset + totalProcessed, 16));
            currentOffset += 16;
            remaining -= 16;
            totalProcessed += 16;
        }

        // 3. Остаток (от 1 до 16 байт) сохраняем в буфер
        if (remaining > 0)
        {
            Array.Copy(inputBuffer, currentOffset, _buffer, _bufferCount, remaining);
            _bufferCount += remaining;
        }

        return totalProcessed;
    }

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        // Собираем всё, что осталось в "депо" и в последнем приходе
        byte[] finalX = new byte[_bufferCount + inputCount];
        Array.Copy(_buffer, 0, finalX, 0, _bufferCount);
        Array.Copy(inputBuffer, inputOffset, finalX, _bufferCount, inputCount);

        if (finalX.Length == 0) return [];
        if (finalX.Length < 16) throw new CryptographicException("CTS требует минимум 128 бит входных данных.");

        int totalLen = finalX.Length;
        int n = (totalLen + 15) / 16;
        int m = totalLen % 16;
        byte[] finalY = new byte[totalLen];

        // Используем твою проверенную математику
        if (m == 0)
        {
            // Пункт 3 стандарта: кратно 128 битам
            for (int i = 0; i < n; i++)
            {
                EncryptStandardBlock(finalX.AsSpan(i * 16, 16), finalY.AsSpan(i * 16, 16));
            }
        }
        else
        {
            // Пункт 4 стандарта: захват шифртекста (CTS)
            // 4.1 Блоки до n-2
            for (int i = 0; i < n - 2; i++)
            {
                EncryptStandardBlock(finalX.AsSpan(i * 16, 16), finalY.AsSpan(i * 16, 16));
            }

            // 4.2 Промежуточный Yn || r
            Span<byte> temp42Input = stackalloc byte[16];
            Xor(finalX.AsSpan((n - 2) * 16, 16), _prevY, temp42Input);

            Span<byte> yn_r = stackalloc byte[16];
            _block.Encrypt(temp42Input, yn_r);

            var yn = yn_r[..m];
            var r = yn_r[m..];

            // 4.3 Формируем Yn-1
            Span<byte> block43Input = stackalloc byte[16];
            for (int i = 0; i < m; i++)
                block43Input[i] = (byte)(finalX[(n - 1) * 16 + i] ^ yn[i]);

            r.CopyTo(block43Input[m..]);

            _block.Encrypt(block43Input, finalY.AsSpan((n - 2) * 16, 16));
            yn.CopyTo(finalY.AsSpan((n - 1) * 16, m));
        }

        return finalY;
    }

    private void EncryptStandardBlock(ReadOnlySpan<byte> x, Span<byte> y)
    {
        Span<byte> xorBuf = stackalloc byte[16];
        Xor(x, _prevY, xorBuf);
        _block.Encrypt(xorBuf, y);
        y.CopyTo(_prevY);
    }
}