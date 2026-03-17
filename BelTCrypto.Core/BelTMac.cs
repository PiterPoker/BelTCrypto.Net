using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTMac : IBelTMac
{
    private readonly IBelTBlock _block;

    public BelTMac(IBelTBlock block) => _block = block ?? throw new ArgumentNullException(nameof(block));

    public void Compute(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Span<byte> mac)
    {
        if (mac.Length < 8)
            throw new ArgumentException("Имитовставка T должна быть 64 бита (8 байт).");

        // 1) Split1(X, 128). Если X пуст, n = 1.
        int totalLen = data.Length;
        int n = (totalLen == 0) ? 1 : (totalLen + 15) / 16;

        // 2) Вычисление вспомогательных ключей финализации
        Span<byte> rBase = stackalloc byte[16];
        rBase.Clear();
        _block.Encrypt(rBase, key, rBase); // r = belt-block(0^128, K)

        Span<byte> s1 = stackalloc byte[16];
        Span<byte> s2 = stackalloc byte[16];
        BelTMath.GfBlock.Phi1(rBase, s1);
        BelTMath.GfBlock.Phi2(rBase, s2);

        // Рабочий регистр s (инициализируется 0^128)
        Span<byte> sReg = stackalloc byte[16];
        sReg.Clear();

        try
        {
            // 3) Цикл по блокам i = 1 ... n-1
            for (int i = 0; i < n - 1; i++)
            {
                BelTMath.GfBlock.Xor(sReg, data.Slice(i * 16, 16));
                _block.Encrypt(sReg, key, sReg);
            }

            // 4, 5) Обработка последнего блока Xn
            int lastOffset = (n - 1) * 16;
            int lastLen = totalLen - lastOffset;

            if (lastLen == 16)
            {
                // Вариант 4: Полный блок
                BelTMath.GfBlock.Xor(sReg, data.Slice(lastOffset, 16));
                BelTMath.GfBlock.Xor(sReg, s1);
            }
            else
            {
                // Вариант 5: Неполный блок (в т.ч. случай X = ⊥)
                Span<byte> psiXn = stackalloc byte[16];
                BelTMath.GfBlock.ApplyPsi(data.Slice(lastOffset, lastLen), psiXn);
                BelTMath.GfBlock.Xor(sReg, psiXn);
                BelTMath.GfBlock.Xor(sReg, s2);
            }

            // 6) T = Lo(belt-block(s, K), 64)
            _block.Encrypt(sReg, key, sReg);

            // 7) Возвратить T (8 байт)
            sReg[..8].CopyTo(mac);
        }
        finally
        {
            // Очистка всех конфиденциальных данных в стеке
            rBase.Clear();
            s1.Clear();
            s2.Clear();
            sReg.Clear();
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> expectedMac)
    {
        // Создаем временный буфер для вычисленного MAC
        Span<byte> actualMac = stackalloc byte[expectedMac.Length];
        try
        {
            Compute(data, key, actualMac);

            // Безопасное сравнение
            return actualMac.SequenceEqual(expectedMac);
        }
        finally
        {
            actualMac.Clear();
        }
    }
}
