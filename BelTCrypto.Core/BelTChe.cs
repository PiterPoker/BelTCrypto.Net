using System.Buffers.Binary;
using System.Security.Cryptography;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTChe : IBelTChe
{
    private readonly IBelTBlock _block;

    public BelTChe(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }
    public void Protect(
ReadOnlySpan<byte> x,
ReadOnlySpan<byte> i,
ReadOnlySpan<byte> k,
ReadOnlySpan<byte> s,
Span<byte> y,
Span<byte> tag)
    {
        // 1. Подготовка длин
        int n = (x.Length + 15) / 16;
        int m = (i.Length + 15) / 16;

        Span<byte> sReg = stackalloc byte[16];
        Span<byte> rReg = stackalloc byte[16];
        Span<byte> tReg = stackalloc byte[16];
        Span<byte> buffer = stackalloc byte[16];

        // 2. Инициализация (belt-che специфичные шаги)
        _block.Encrypt(s, k, sReg);     // s = belt-block(S, K)
        sReg.CopyTo(rReg);              // r = s
        Core.BelTMath.H[..16].CopyTo(tReg); // t = H (константа из стандарта)

        // 3. Обработка ассоциированных данных I
        for (int j = 0; j < m; j++)
        {
            int offset = j * 16;
            int len = System.Math.Min(16, i.Length - offset);
            buffer.Clear();
            i.Slice(offset, len).CopyTo(buffer);

            Core.BelTMath.GfBlock.Xor(tReg, buffer);
            Core.BelTMath.GfBlock.Multiply(tReg, rReg);
        }

        // 4. Шифрование X и накопление контрольной суммы по Y
        for (int j = 0; j < n; j++)
        {
            // 4.1 Обновление состояния: s = (s * C) ^ <1>128
            Core.BelTMath.GfBlock.Multiply(sReg, Core.BelTMath.C);
            sReg[0] ^= 0x01;

            // 4.2 Шифрование блока: Yi = Xi ^ Lo(belt-block(s, K), |Xi|)
            _block.Encrypt(sReg, k, buffer);
            int offset = j * 16;
            int len = System.Math.Min(16, x.Length - offset);

            for (int b = 0; b < len; b++)
            {
                y[offset + b] = (byte)(x[offset + b] ^ buffer[b]);
            }

            // 4.3 - 4.4 Добавление Yi в имитовставку: t = (t ^ Yi) * r
            buffer.Clear();
            y.Slice(offset, len).CopyTo(buffer); // Берем уже зашифрованный блок
            Core.BelTMath.GfBlock.Xor(tReg, buffer);
            Core.BelTMath.GfBlock.Multiply(tReg, rReg);
        }

        // 5. Добавление длин (в битах)
        buffer.Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(buffer[0..8], (ulong)i.Length * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer[8..16], (ulong)x.Length * 8);
        Core.BelTMath.GfBlock.Xor(tReg, buffer);

        // 6. Финализация имитовставки
        Core.BelTMath.GfBlock.Multiply(tReg, rReg);
        _block.Encrypt(tReg, k, tReg);

        // 7-8. Результат: (Y, Lo(t, 64))
        tReg[..8].CopyTo(tag);
    }

    public bool Unprotect(
    ReadOnlySpan<byte> y,
    ReadOnlySpan<byte> i,
    ReadOnlySpan<byte> k,
    ReadOnlySpan<byte> s,
    ReadOnlySpan<byte> tExpected,
    Span<byte> x)
    {
        // 1. Определение количества блоков (Шаг 1)
        int n = (y.Length + 15) / 16;
        int m = (i.Length + 15) / 16;

        Span<byte> sReg = stackalloc byte[16];
        Span<byte> rReg = stackalloc byte[16];
        Span<byte> tReg = stackalloc byte[16];
        Span<byte> buffer = stackalloc byte[16];

        try
        {
            // 2. Инициализация (Шаг 2)
            _block.Encrypt(s, k, sReg);         // s ← belt-block(S,K)
            sReg.CopyTo(rReg);                  // r ← s
            Core.BelTMath.H[..16].CopyTo(tReg); // t ← H (константа B194...)

            // 3. Обработка ассоциированных данных I (Шаг 3)
            for (int j = 0; j < m; j++)
            {
                int offset = j * 16;
                int len = System.Math.Min(16, i.Length - offset);
                buffer.Clear();
                i.Slice(offset, len).CopyTo(buffer);

                Core.BelTMath.GfBlock.Xor(tReg, buffer);   // t ← t ⊕ (Ii || 0)
                Core.BelTMath.GfBlock.Multiply(tReg, rReg); // t ← t * r
            }

            // 4 и 8. Обработка Y и восстановление X (Примечание 2: совмещаем шаги)
            for (int j = 0; j < n; j++)
            {
                int offset = j * 16;
                int len = System.Math.Min(16, y.Length - offset);

                // Шаг 4: Накопление имитовставки по блоку Yi
                buffer.Clear();
                y.Slice(offset, len).CopyTo(buffer);
                Core.BelTMath.GfBlock.Xor(tReg, buffer);    // t ← t ⊕ (Yi || 0)
                Core.BelTMath.GfBlock.Multiply(tReg, rReg);  // t ← t * r

                // Шаг 8: Расшифрование блока Yi -> Xi
                Core.BelTMath.GfBlock.Multiply(sReg, Core.BelTMath.C); // s ← (s * C)
                sReg[0] ^= 0x01;                                      // s ← s ⊕ <1>128

                _block.Encrypt(sReg, k, buffer); // Гамма = belt-block(s, K)
                for (int b = 0; b < len; b++)
                {
                    x[offset + b] = (byte)(y[offset + b] ^ buffer[b]); // Xi ← Yi ⊕ Lo(гамма)
                }
            }

            // 5. Добавление длин (Шаг 5)
            buffer.Clear();
            BinaryPrimitives.WriteUInt64LittleEndian(buffer[0..8], (ulong)i.Length * 8);
            BinaryPrimitives.WriteUInt64LittleEndian(buffer[8..16], (ulong)y.Length * 8);
            Core.BelTMath.GfBlock.Xor(tReg, buffer); // t ← t ⊕ (|I| || |Y|)

            // 6. Финализация (Шаг 6)
            Core.BelTMath.GfBlock.Multiply(tReg, rReg); // t ← t * r
            _block.Encrypt(tReg, k, tReg);              // t ← belt-block(t, K)

            // 7. Проверка имитовставки (Шаг 7 и Примечание 1)
            // Сравниваем вычисленное Lo(t, |T|) с ожидаемым T
            if (CryptographicOperations.FixedTimeEquals(tReg[..tExpected.Length], tExpected))
            {
                // 9. Возвратить X (Шаг 9)
                return true;
            }

            // Если проверка не прошла — возвращаем ложь и затираем X
            x.Clear();
            return false;
        }
        finally
        {
            // Очистка временных регистров
            CryptographicOperations.ZeroMemory(sReg);
            CryptographicOperations.ZeroMemory(rReg);
            CryptographicOperations.ZeroMemory(tReg);
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}