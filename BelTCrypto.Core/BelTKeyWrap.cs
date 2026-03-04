using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

public sealed class BelTKeyWrap(IBelTWideBlock wideBlock)
{
    private readonly IBelTWideBlock _wideBlock = wideBlock;

    public void Wrap(ReadOnlySpan<byte> input, Span<byte> output)
    {
        // 1. Проверка длины: выход должен быть на 16 байт больше входа
        if (output.Length != input.Length + 16)
            throw new ArgumentException("Output buffer must be input.Length + 16");

        // 2. Создаем временный буфер Z = X || I
        byte[] z = new byte[input.Length + 16];
        input.CopyTo(z.AsSpan(0, input.Length));
        BelTMath.SyncHeader.CopyTo(z.AsSpan(input.Length, 16));

        // 3. Применяем belt-wblock к Z
        // Важно: теперь n будет считаться от 47 байт, а не от 31!
        _wideBlock.Encrypt(z, output);
    }

    /*public void Unwrap(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < 16 || output.Length != input.Length - 16)
            throw new ArgumentException("Invalid buffer sizes for unwrap");

        // 1. Применяем обратный широкий блок belt-wblock-1
        byte[] z = new byte[input.Length];
        _wideBlock.Decrypt(input, z);

        // 2. Проверяем синхропосылку в конце (последние 16 байт)
        var headerPart = z.AsSpan(z.Length - 16);
        if (!headerPart.SequenceEqual(BelTMath.SyncHeader))
            throw new CryptographicException("Integrity check failed: invalid sync header.");

        // 3. Копируем результат (ключ) обратно
        z.AsSpan(0, output.Length).CopyTo(output);
    }*/
}
