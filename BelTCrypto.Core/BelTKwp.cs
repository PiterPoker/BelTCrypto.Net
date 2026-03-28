using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal class BelTKwp : IBelTKwp
{
    private readonly IBelTWideBlock _block;

    public BelTKwp(IBelTWideBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }

    public void Protect(ReadOnlySpan<byte> x, ReadOnlySpan<byte> i, ReadOnlySpan<byte> k, Span<byte> y)
    {
        // 1. Валидация входных данных (fail-fast)
        if (x.Length < 16) throw new ArgumentException("Ключ X слишком короткий.");
        if (i.Length != 16) throw new ArgumentException("Заголовок I должен быть 128 бит.");

        // 2. Безопасное выделение памяти
        // Используем stackalloc для предотвращения попадания ключа в кучу (GC)
        // y.Length всегда >= 32 байт, так что это безопасно для стека
        Span<byte> z = stackalloc byte[y.Length];

        try
        {
            x.CopyTo(z[..x.Length]);
            i.CopyTo(z[x.Length..]);

            // 3. Вызов широкоблочного шифра (Шаг 1: Y ← belt-wblock(Z, K))
            _block.Encrypt(z, k, y);
        }
        finally
        {
            // Стираем промежуточную склейку Z из памяти сразу после использования
            CryptographicOperations.ZeroMemory(z);
        }
    }

    public bool Unprotect(ReadOnlySpan<byte> y, ReadOnlySpan<byte> i, ReadOnlySpan<byte> k, Span<byte> x)
    {
        // Шаг 1: Проверка длины и кратности (минимум 32 байта)
        if (y.Length < 32 || (y.Length % 16 != 0))
        {
            if (x.Length > 0) x.Clear();
            return false;
        }

        // Временный буфер для расшифрованного Z = (X || r)
        Span<byte> z = stackalloc byte[y.Length];

        try
        {
            // Шаг 2: (X || r) ← belt-wblock⁻¹(Y, K)
            _block.Decrypt(y, k, z);

            int xLen = y.Length - 16;
            ReadOnlySpan<byte> restoredX = z[..xLen];
            ReadOnlySpan<byte> r = z[xLen..];

            // Шаг 3: Если r != I, то возвратить ⊥ (false)
            if (!CryptographicOperations.FixedTimeEquals(r, i))
            {
                if (x.Length > 0) x.Clear();
                return false;
            }

            // Шаг 4: Возвратить X
            // Если проверка пройдена, копируем результат в выходной Span
            restoredX.CopyTo(x);
            return true;
        }
        finally
        {
            // Очистка всех копий секретного ключа в памяти стека
            CryptographicOperations.ZeroMemory(z);
        }
    }
}
