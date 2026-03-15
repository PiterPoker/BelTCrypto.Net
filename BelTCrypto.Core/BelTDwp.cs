using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces.Old;
using BelTCrypto.Core.Old;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal sealed class BelTDwp(IBelTBlockOld block) : BelTAead(block)
{
    // Первая строка Таблицы 2 (индексы 0..15)
    private static readonly byte[] T_INIT = BelTMathOld.SBoxH[..16];

    public override (byte[] CipherText, byte[] Tag) Protect(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> iv)
    {
        // 1. Установка
        byte[] s = new byte[16];
        _block.Encrypt(iv, s);
        byte[] r = new byte[16];
        _block.Encrypt(s, r);
        byte[] t = (byte[])T_INIT.Clone();

        // 2. Имитовставка от ассоциированных данных (Шаг 3)
        UpdateTag(t, r, associatedData);

        // 3. Шифрование (гаммирование) (Шаг 4)
        byte[] y = new byte[message.Length];
        byte[] s_gamma = (byte[])s.Clone();
        byte[] gamma = new byte[16];
        for (int i = 0; i < message.Length; i += 16)
        {
            int chunkSize = Math.Min(16, message.Length - i);
            BelTMathOld.Increment128(s_gamma);
            _block.Encrypt(s_gamma, gamma);
            for (int j = 0; j < chunkSize; j++)
                y[i + j] = (byte)(message[i + j] ^ gamma[j]);
        }

        // 4. Имитовставка от шифртекста (Шаг 4.3)
        UpdateTag(t, r, y);

        // 5. Финализация имитовставки (Шаги 5-6)
        FinalizeTag(t, r, associatedData.Length, message.Length);

        byte[] tag = new byte[8];
        t.AsSpan(0, 8).CopyTo(tag);
        return (y, tag);
    }

    public override byte[] Unprotect(ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> tag)
    {
        // 1. Установка (Шаг 2)
        byte[] s = new byte[16];
        _block.Encrypt(iv, s);
        byte[] r = new byte[16];
        _block.Encrypt(s, r);

        byte[] t = (byte[])T_INIT.Clone();

        // 2. Имитовставка от AD (Шаг 3)
        UpdateTag(t, r, associatedData);

        // 3. Имитовставка от CipherText (Шаг 4.3)
        UpdateTag(t, r, cipherText);

        // 4. Блок длин (Шаг 5)
        Span<byte> lengths = stackalloc byte[16];
        // СТБ требует длину в битах (длина в байтах * 8)
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[0..8], (ulong)associatedData.Length * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..16], (ulong)cipherText.Length * 8);

        for (int i = 0; i < 16; i++) t[i] ^= lengths[i];

        // 5. Финализация (Шаг 6)
        BelTMathOld.MultiplyGF128(t, r);
        _block.Encrypt(t, t);

        // 6. Проверка (Шаг 7) - берем первые 8 байт (64 бита) [cite: 106]
        if (!t.AsSpan(0, 8).SequenceEqual(tag))
            throw new CryptographicException("⊥");

        // 7. Расшифрование (Шаг 8)
        byte[] message = new byte[cipherText.Length];
        byte[] s_gamma = (byte[])s.Clone();
        byte[] gamma = new byte[16];
        for (int i = 0; i < cipherText.Length; i += 16)
        {
            int chunkSize = Math.Min(16, cipherText.Length - i);
            BelTMathOld.Increment128(s_gamma);
            _block.Encrypt(s_gamma, gamma);
            for (int j = 0; j < chunkSize; j++)
                message[i + j] = (byte)(cipherText[i + j] ^ gamma[j]);
        }
        return message;
    }

    private void UpdateTag(byte[] t, byte[] r, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;

        Span<byte> blockBuf = stackalloc byte[16];
        for (int i = 0; i < data.Length; i += 16)
        {
            int chunkSize = Math.Min(16, data.Length - i);

            blockBuf.Clear(); // Обязательно обнуляем!
            data.Slice(i, chunkSize).CopyTo(blockBuf);

            // 1. XOR t = t ⊕ (блок данных)
            for (int j = 0; j < 16; j++)
                t[j] ^= blockBuf[j];

            // 2. Умножение t = t * r
            BelTMathOld.MultiplyGF128(t, r);
        }
    }

    private void FinalizeTag(byte[] t, byte[] r, long adLen, long msgLen)
    {
        Span<byte> lengths = stackalloc byte[16];
        // Длины в битах, Little-Endian
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[0..8], (ulong)adLen * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..16], (ulong)msgLen * 8);

        // XOR с блоком длин
        for (int i = 0; i < 16; i++) t[i] ^= lengths[i];

        // t = t * r
        BelTMathOld.MultiplyGF128(t, r);

        // Финальное шифрование блока
        _block.Encrypt(t, t);
    }
}