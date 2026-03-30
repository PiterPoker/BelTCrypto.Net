using BelTCrypto.Core.Interfaces;
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal class BelTFmt : IBelTFmt
{
    private readonly IBelTBlock _block;
    private readonly IBelTWideBlock _wideBlock;

    public BelTFmt(IBelTBlock block, IBelTWideBlock wideBlock)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
        _wideBlock = wideBlock ?? throw new ArgumentNullException(nameof(wideBlock));
    }
    public void Decrypt(ReadOnlySpan<ushort> y, int m, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<ushort> x)
    {
        // 1. Подготовка (как в твоем Encrypt)
        int n = y.Length;
        int n1 = (n + 1) / 2;
        int n2 = n / 2;

        int b1 = (int)Math.Ceiling(n1 * Math.Log2(m) / 64.0) * 64;
        int b2 = (int)Math.Ceiling(n2 * Math.Log2(m) / 64.0) * 64;

        // ТВОЯ подготовка S (прямо из твоего метода Encrypt)
        Span<uint> sExt = stackalloc uint[6];
        uint fmtInfo = (uint)(m & 0xFFFF) | ((uint)(n & 0xFFFF) << 16);
        sExt[0] = fmtInfo;
        sExt[5] = fmtInfo;
        for (int i = 0; i < 4; i++)
        {
            sExt[i + 1] = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(i * 4, 4));
        }

        // ТВОИ константы C
        var c = BelTMath.H24();

        // Шаг 1: r ← Y
        Span<ushort> r1 = stackalloc ushort[n1];
        Span<ushort> r2 = stackalloc ushort[n2];
        y[..n1].CopyTo(r1);
        y[n1..].CopyTo(r2);

        // Шаг 2: Итерации i=3, 2, 1 (Расшифрование — зеркально)
        for (int i = 3; i >= 1; i--)
        {
            // ВНИМАНИЕ: Сначала правим r2, используя r1 (индексы 2i-1)
            ApplyFeistelStepInverse(r1, r2, m, b1, n2, c[2 * i - 1], sExt[2 * i - 1], k);

            // Затем правим r1, используя r2 (индексы 2i-2)
            ApplyFeistelStepInverse(r2, r1, m, b2, n1, c[2 * i - 2], sExt[2 * i - 2], k);
        }

        // Шаг 3-4: Склеиваем и возвращаем
        r1.CopyTo(x[..n1]);
        r2.CopyTo(x[n1..]);
    }

    private void ApplyFeistelStepInverse(ReadOnlySpan<ushort> passive, Span<ushort> active, int m, int bj, int nj, uint ci, uint si, ReadOnlySpan<byte> k)
    {
        int dataBytes = bj / 8;
        Span<byte> t = stackalloc byte[dataBytes + 8];

        // 1. str2bin (ТВОЙ BlockUtils)
        BlockUtils.Str2Bin(passive, m, t[..dataBytes]);

        // 2. Записываем константы (Как в твоем коде)
        BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(dataBytes, 4), ci);
        BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(dataBytes + 4, 4), si);

        // 3. RoundF (ТВОЙ метод)
        RoundF(t, k);

        // 4. bin2str (ТВОЙ BlockUtils)
        Span<ushort> offset = stackalloc ushort[nj];
        BlockUtils.Bin2Str(t, m, nj, offset);

        // 5. Вычитание по модулю m (Операция ⊖ из стандарта)
        for (int j = 0; j < nj; j++)
        {
            int diff = active[j] - (offset[j] % m);
            if (diff < 0) diff += m;
            active[j] = (ushort)(diff % m);
        }
    }

    public void Encrypt(ReadOnlySpan<ushort> x, int m, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<ushort> y)
    {
        int n = x.Length;
        int n1 = (n + 1) / 2;
        int n2 = n / 2;

        int b1 = (int)Math.Ceiling(n1 * Math.Log2(m) / 64.0) * 64;
        int b2 = (int)Math.Ceiling(n2 * Math.Log2(m) / 64.0) * 64;

        // --- ИСПРАВЛЕНИЕ №2 и №3 (Подготовка S и C) ---
        Span<uint> sExt = stackalloc uint[6];

        // S0 = <m>_16 || <n>_16. В памяти это [m_low, m_high, n_low, n_high]
        // Чтобы BinaryPrimitives.WriteUInt32LittleEndian сработал верно, собираем uint так:
        uint fmtInfo = (uint)(m & 0xFFFF) | ((uint)(n & 0xFFFF) << 16);
        sExt[0] = fmtInfo;
        sExt[5] = fmtInfo;

        for (int i = 0; i < 4; i++)
        {
            // Читаем S1..S4 как LittleEndian, чтобы порядок байт в блоке t соответствовал СТБ
            sExt[i + 1] = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(i * 4, 4));
        }

        // Константы C должны быть считаны как LittleEndian из таблицы H
        // Если BelTMath.C6() внутри использует BigEndian - это сломает всё.
        // Правильно: BinaryPrimitives.ReadUInt32LittleEndian(H.AsSpan(0, 4)) -> 0xC8BA94B1
        var c = BelTMath.H24();

        Span<ushort> r1 = stackalloc ushort[n1];
        Span<ushort> r2 = stackalloc ushort[n2];
        x[..n1].CopyTo(r1);
        x[n1..].CopyTo(r2);

        for (int i = 1; i <= 3; i++)
        {
            ApplyFeistelStep(r2, r1, m, b2, n1, c[2 * i - 2], sExt[2 * i - 2], k);
            ApplyFeistelStep(r1, r2, m, b1, n2, c[2 * i - 1], sExt[2 * i - 1], k);
        }

        r1.CopyTo(y[..n1]);
        r2.CopyTo(y[n1..]);
    }

    private void ApplyFeistelStep(ReadOnlySpan<ushort> passive, Span<ushort> active, int m, int bj, int nj, uint ci, uint si, ReadOnlySpan<byte> k)
    {
        // bj - это 64. Значит bj/8 = 8 байт данных.
        // Общий размер t = 8 + 4 (Ci) + 4 (Si) = 16 байт.
        int dataBytes = bj / 8;
        Span<byte> t = stackalloc byte[dataBytes + 8];

        // 1. str2bin (Заполняем t[0..7])
        BlockUtils.Str2Bin(passive, m, t[..dataBytes]);

        // 2. Записываем константы (Заполняем t[8..11] и t[12..15])
        BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(dataBytes, 4), ci);
        BinaryPrimitives.WriteUInt32LittleEndian(t.Slice(dataBytes + 4, 4), si);

        // 3. RoundF (Шифруем ВЕСЬ блок 16 байт)
        RoundF(t, k);

        // Передаем в bin2str ВЕСЬ зашифрованный блок t (16 байт), а не t[..8]!
        Span<ushort> offset = stackalloc ushort[nj];
        BlockUtils.Bin2Str(t, m, nj, offset);

        for (int j = 0; j < nj; j++)
        {
            active[j] = (ushort)((active[j] + offset[j]) % m);
        }
    }

    private void Belt32Block(Span<byte> t, ReadOnlySpan<byte> k)
    {
        Span<byte> buffer = stackalloc byte[16];
        Span<byte> t1Old = stackalloc byte[8]; // Вынесли из цикла

        for (int i = 1; i <= 3; i++)
        {
            // 1) Копируем t[8..23] в буфер для шифрования
            t.Slice(8, 16).CopyTo(buffer);
            _block.Encrypt(buffer, k, buffer);

            // XOR младших 8 байт с i
            ulong low = BinaryPrimitives.ReadUInt64LittleEndian(buffer[..8]);
            BinaryPrimitives.WriteUInt64LittleEndian(buffer[..8], low ^ (ulong)i);

            // 2) Сохраняем старый t1 (0..7)
            t[..8].CopyTo(t1Old);

            // 3) Обновляем t: t1 и t2 становятся результатом шифрования
            buffer.CopyTo(t[..16]);

            // 4) Новое t3 вычисляется как XOR старого t1 и нового t1
            for (int j = 0; j < 8; j++)
                t[16 + j] = (byte)(t1Old[j] ^ t[j]);

            // (Опционально) Очистка временного буфера для безопасности
            t1Old.Clear();
        }
    }

    private void RoundF(Span<byte> t, ReadOnlySpan<byte> k)
    {
        int bitLength = t.Length * 8;

        switch (bitLength)
        {
            case 128:
                _block.Encrypt(t, k, t);
                break;
            case 192:
                Belt32Block(t, k);
                break;
            default:
                if (bitLength >= 256)
                    _wideBlock.Encrypt(t, k, t);
                else
                    throw new CryptographicException("Неверная длина блока для roundf");
                break;
        }
    }
}
