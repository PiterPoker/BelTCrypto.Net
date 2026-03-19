using BelTCrypto.Core.Interfaces;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal class BelTDwp : IBelTDwp
{
    private readonly IBelTBlock _block;

    public BelTDwp(IBelTBlock block)
    {
        _block = block;
    }
    public void Protect(ReadOnlySpan<byte> x, ReadOnlySpan<byte> i, ReadOnlySpan<byte> key, ReadOnlySpan<byte> s, Span<byte> y, Span<byte> t)
    {
        if (t.Length < 8) throw new ArgumentException("T must be 64 bits.");
        if (y.Length != x.Length) throw new ArgumentException("Output buffer Y must match input X length.");

        // Секретные регистры в стеке
        Span<byte> rReg = stackalloc byte[16];
        Span<byte> sReg = stackalloc byte[16];
        Span<byte> tReg = stackalloc byte[16];

        try
        {
            // 2) Инициализация
            _block.Encrypt(s, key, sReg);      // s = belt-block(S, K)
            _block.Encrypt(sReg, key, rReg);   // r = belt-block(s, K)

            // Инициализация t константой H[0..15]
            BelTMath.H.AsSpan(0, 16).CopyTo(tReg);

            // 3) Обработка ассоциированных данных I
            UpdateAeadHash(i, rReg, tReg);

            // 4) Шифрование X -> Y и одновременное хеширование Y
            EncryptAndHash(x, y, key, rReg, sReg, tReg);

            // 5-6) Финализация имитовставки (длины + финальный belt-block)
            FinalizeTag(i.Length, x.Length, key, rReg, tReg);

            // 7) T = Lo(t, 64)
            tReg[..8].CopyTo(t);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rReg);
            CryptographicOperations.ZeroMemory(sReg);
            CryptographicOperations.ZeroMemory(tReg);
        }
    }

    public bool Unprotect(ReadOnlySpan<byte> y, ReadOnlySpan<byte> i, ReadOnlySpan<byte> t, ReadOnlySpan<byte> key, ReadOnlySpan<byte> s, Span<byte> x)
    {
        if (t.Length != 8) return false;
        if (x.Length != y.Length) return false;

        Span<byte> rReg = stackalloc byte[16];
        Span<byte> sReg = stackalloc byte[16];
        Span<byte> tReg = stackalloc byte[16];

        try
        {
            // 2) Инициализация
            _block.Encrypt(s, key, sReg);
            _block.Encrypt(sReg, key, rReg);
            BelTMath.H.AsSpan(0, 16).CopyTo(tReg);

            // 3-4) Накопление хеша от I и Y
            UpdateAeadHash(i, rReg, tReg);
            UpdateAeadHash(y, rReg, tReg);

            // 5-6) Финализация
            FinalizeTag(i.Length, y.Length, key, rReg, tReg);

            // 7) Проверка имитовставки в константное время
            if (!CryptographicOperations.FixedTimeEquals(t, tReg[..8]))
            {
                x.Clear(); // Не выдаем мусор при ошибке
                return false;
            }

            // 8) Расшифрование (только если T верно)
            // Восстанавливаем начальное состояние гаммы
            _block.Encrypt(s, key, sReg);
            Decrypt(y, x, key, sReg);

            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rReg);
            CryptographicOperations.ZeroMemory(sReg);
            CryptographicOperations.ZeroMemory(tReg);
        }
    }

    private void UpdateAeadHash(ReadOnlySpan<byte> data, ReadOnlySpan<byte> r, Span<byte> t)
    {
        int n = (data.Length + 15) / 16;
        Span<byte> block = stackalloc byte[16];

        try
        {
            for (int j = 0; j < n; j++)
            {
                int offset = j * 16;
                int len = Math.Min(16, data.Length - offset);

                block.Clear();
                data.Slice(offset, len).CopyTo(block);

                BelTMath.GfBlock.Xor(t, block);
                BelTMath.GfBlock.Multiply(t, r);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    private void EncryptAndHash(ReadOnlySpan<byte> x, Span<byte> y, ReadOnlySpan<byte> key, ReadOnlySpan<byte> r, Span<byte> s, Span<byte> t)
    {
        int n = (x.Length + 15) / 16;
        Span<byte> gamma = stackalloc byte[16];
        Span<byte> yiFull = stackalloc byte[16];

        try
        {
            for (int j = 0; j < n; j++)
            {
                BelTMath.Block.Increment(s);
                _block.Encrypt(s, key, gamma);

                int offset = j * 16;
                int len = Math.Min(16, x.Length - offset);

                for (int k = 0; k < len; k++)
                    y[offset + k] = (byte)(x[offset + k] ^ gamma[k]);

                yiFull.Clear();
                y.Slice(offset, len).CopyTo(yiFull);
                BelTMath.GfBlock.Xor(t, yiFull);
                BelTMath.GfBlock.Multiply(t, r);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(gamma);
            CryptographicOperations.ZeroMemory(yiFull);
        }
    }

    private void FinalizeTag(int iLen, int xLen, ReadOnlySpan<byte> key, ReadOnlySpan<byte> r, Span<byte> t)
    {
        Span<byte> lengthsBlock = stackalloc byte[16];
        try
        {
            BinaryPrimitives.WriteUInt64LittleEndian(lengthsBlock[..8], (ulong)iLen * 8);
            BinaryPrimitives.WriteUInt64LittleEndian(lengthsBlock[8..], (ulong)xLen * 8);

            BelTMath.GfBlock.Xor(t, lengthsBlock);

            // Шаг 6: t = belt-block(t * r, K)
            BelTMath.GfBlock.Multiply(t, r);
            _block.Encrypt(t, key, t);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(lengthsBlock);
        }
    }

    private void Decrypt(ReadOnlySpan<byte> y, Span<byte> x, ReadOnlySpan<byte> key, Span<byte> s)
    {
        int n = (y.Length + 15) / 16;
        Span<byte> gamma = stackalloc byte[16];

        try
        {
            for (int j = 0; j < n; j++)
            {
                BelTMath.Block.Increment(s);
                _block.Encrypt(s, key, gamma);

                int offset = j * 16;
                int len = Math.Min(16, y.Length - offset);

                for (int k = 0; k < len; k++)
                    x[offset + k] = (byte)(y[offset + k] ^ gamma[k]);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(gamma);
        }
    }
}
