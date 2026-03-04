using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal sealed class BelTEcb(IBelTBlock block) : IBelTEcb
{
    private readonly IBelTBlock _block = block ?? throw new ArgumentNullException(nameof(block));
    private bool _disposed;

    public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < 16)
            throw new ArgumentException("Message length must be at least 128 bits (16 bytes).");

        int totalLen = input.Length;
        int n = (totalLen + 15) / 16;
        int lastBlockLen = totalLen % 16;

        // 2. Если последний блок полный (|Xn| = 128 бит / 16 байт)
        if (lastBlockLen == 0)
        {
            for (int i = 0; i < n; i++)
            {
                _block.Encrypt(input.Slice(i * 16, 16), output.Slice(i * 16, 16));
            }
        }
        // 3. Если есть неполный блок (|Xn| < 128 бит)
        else
        {
            // 3.1) Шифруем блоки с 1 по n-2
            for (int i = 0; i < n - 2; i++)
            {
                _block.Encrypt(input.Slice(i * 16, 16), output.Slice(i * 16, 16));
            }

            // 3.2) (Yn || r) <- belt-block(Xn-1, K)
            // Шифруем предпоследний блок
            Span<byte> tempYn_r = stackalloc byte[16];
            _block.Encrypt(input.Slice((n - 2) * 16, 16), tempYn_r);

            // Yn — это первые 'lastBlockLen' байт из зашифрованного Xn-1
            tempYn_r[..lastBlockLen].CopyTo(output.Slice((n - 1) * 16, lastBlockLen));

            // r — это оставшаяся часть
            ReadOnlySpan<byte> r = tempYn_r[lastBlockLen..];

            // 3.3) Yn-1 <- belt-block(Xn || r, K)
            // Формируем блок для шифрования предпоследнего места в выходе
            Span<byte> xn_r = stackalloc byte[16];
            input[((n - 1) * 16)..].CopyTo(xn_r); // Копируем неполный Xn
            r.CopyTo(xn_r[lastBlockLen..]);      // Дописываем r в хвост

            _block.Encrypt(xn_r, output.Slice((n - 2) * 16, 16));
        }
    }

    public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < 16)
            throw new ArgumentException("Ciphertext length must be at least 128 bits (16 bytes).");

        int totalLen = input.Length;
        int n = (totalLen + 15) / 16;
        int lastBlockLen = totalLen % 16;

        // 2. Если последний блок полный (|Yn| = 128 бит)
        if (lastBlockLen == 0)
        {
            for (int i = 0; i < n; i++)
            {
                _block.Decrypt(input.Slice(i * 16, 16), output.Slice(i * 16, 16));
            }
        }
        // 3. Если есть неполный блок (|Yn| < 128 бит)
        else
        {
            // 3.1) Расшифроввываем блоки с 1 по n-2
            for (int i = 0; i < n - 2; i++)
            {
                _block.Decrypt(input.Slice(i * 16, 16), output.Slice(i * 16, 16));
            }

            // 3.2) (Xn || r) <- belt-block^-1(Yn-1, K)
            // ВАЖНО: В режиме захвата шифра Yn-1 — это полный блок на позиции n-2
            Span<byte> xn_r = stackalloc byte[16];
            _block.Decrypt(input.Slice((n - 2) * 16, 16), xn_r);

            // Извлекаем восстановленный Xn (первые lastBlockLen байт)
            xn_r[..lastBlockLen].CopyTo(output.Slice((n - 1) * 16, lastBlockLen));

            // Извлекаем r (оставшаяся часть)
            ReadOnlySpan<byte> r = xn_r[lastBlockLen..];

            // 3.3) Xn-1 <- belt-block^-1(Yn || r, K)
            // Формируем блок из неполного Yn и полученного r
            Span<byte> yn_r = stackalloc byte[16];
            input[((n - 1) * 16)..].CopyTo(yn_r); // Копируем Yn
            r.CopyTo(yn_r[lastBlockLen..]);      // Дописываем r

            _block.Decrypt(yn_r, output.Slice((n - 2) * 16, 16));
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            _block?.Dispose();
        }

        _disposed = true;
    }
}