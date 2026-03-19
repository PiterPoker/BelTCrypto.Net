using BelTCrypto.Core.Interfaces;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace BelTCrypto.Core;

internal class BelTBlock : IBelTBlock
{
    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, Span<byte> x)
    {
        if (k.Length != 32) throw new ArgumentException("Ключ — 256 бит.");

        // Шаг 1 и 4: Читаем Y как (a, b, c, d)
        var (a, b, c, d) = BlockUtils.ReadUInt32LittleEndian(y);

        Span<uint> masterKeys = stackalloc uint[8];

        try
        {
            for (int i = 0; i < 8; i++)
                masterKeys[i] = BinaryPrimitives.ReadUInt32LittleEndian(k[(i * 4)..(i * 4 + 4)]);

            // Шаг 5: Цикл i = 8...1
            for (int i = 8; i >= 1; i--)
            {
                (a, b, c, d) = ExecuteDecryptStep(a, b, c, d, masterKeys, (uint)i);
            }

            // Шаг 6: X ← c ‖ a ‖ d ‖ b
            BlockUtils.WriteUInt32LittleEndian(c, a, d, b, x);
        }
        finally
        {
            masterKeys.Clear();
            a = b = c = d = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static (uint a, uint b, uint c, uint d) ExecuteDecryptStep(uint a, uint b, uint c, uint d, Span<uint> k, uint step)
    {
        static uint GetK(Span<uint> k, int j) => k[(j - 1) % 8];
        int i = (int)step;

        // 5.1) b ← b ⊕ G5(a ⊞ k[7i])
        b ^= BelTMath.G(a + GetK(k, 7 * i), 5);

        // 5.2) c ← c ⊕ G21(d ⊞ k[7i-1])
        c ^= BelTMath.G(d + GetK(k, 7 * i - 1), 21);

        // 5.3) a ← a ⊟ G13(b ⊞ k[7i-2])
        a -= BelTMath.G(b + GetK(k, 7 * i - 2), 13);

        // 5.4) e ← G21(b ⊞ c ⊞ k[7i-3]) ⊕ ⟨i⟩32
        uint e = BelTMath.G(b + c + GetK(k, 7 * i - 3), 21) ^ (uint)i;

        // 5.5) b ← b ⊞ e
        b += e;

        // 5.6) c ← c ⊟ e
        c -= e;

        // 5.7) d ← d ⊞ G13(c ⊞ k[7i-4])
        d += BelTMath.G(c + GetK(k, 7 * i - 4), 13);

        // 5.8) b ← b ⊕ G21(a ⊞ k[7i-5])
        b ^= BelTMath.G(a + GetK(k, 7 * i - 5), 21);

        // 5.9) c ← c ⊕ G5(d ⊞ k[7i-6])
        c ^= BelTMath.G(d + GetK(k, 7 * i - 6), 5);

        return (c, a, d, b);
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, Span<byte> y)
    {
        if (k.Length != 32) throw new ArgumentException("Ключ должен быть 256 бит.");

        var (a, b, c, d) = BlockUtils.ReadUInt32LittleEndian(x);

        // 2. Развертывание ключа (извлечение 8 тактовых ключей)
        // В простейшем случае это просто 8 uint-ов из 32-байтового массива
        Span<uint> roundKeys = stackalloc uint[8];
        try
        {
            for (int i = 0; i < 8; i++)
                roundKeys[i] = BinaryPrimitives.ReadUInt32LittleEndian(k[(i * 4)..(i * 4 + 4)]);

            // 3. Основной цикл — 8 тактов
            for (int i = 1; i <= 8; i++)
            {
                (a, b, c, d) = ExecuteEncryptStep(a, b, c, d, roundKeys, (uint)i);
            }

            BlockUtils.WriteUInt32LittleEndian(b, d, a, c, y);

        }
        finally
        {
            roundKeys.Clear();
            a = b = c = d = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static (uint a, uint b, uint c, uint d) ExecuteEncryptStep(uint a, uint b, uint c, uint d, Span<uint> k, uint step)
    {
        // Вспомогательная функция для k[j] = K((j-1) mod 8 + 1)
        // Так как в C# индексы от 0 до 7, формула превращается в (j-1) % 8
        static uint GetK(Span<uint> k, int j) => k[(j - 1) % 8];

        int t = (int)step;

        // 1) b ← b ⊕ G5(a ⊞ k[7i-6])
        b ^= BelTMath.G(a + GetK(k, 7 * t - 6), 5);

        // 2) c ← c ⊕ G21(d ⊞ k[7i-5])
        c ^= BelTMath.G(d + GetK(k, 7 * t - 5), 21);

        // 3) a ← a ⊟ G13(b ⊞ k[7i-4])
        a -= BelTMath.G(b + GetK(k, 7 * t - 4), 13);

        // 4) e ← G21(b ⊞ c ⊞ k[7i-3]) ⊕ ⟨i⟩32
        var e = BelTMath.G(b + c + GetK(k, 7 * t - 3), 21) ^ step;

        // 5) b ← b ⊞ e
        b += e;

        // 6) c ← c ⊟ e
        c -= e;

        // 7) d ← d ⊞ G13(c ⊞ k[7i-2])
        d += BelTMath.G(c + GetK(k, 7 * t - 2), 13);

        // 8) b ← b ⊕ G21(a ⊞ k[7i-1])
        b ^= BelTMath.G(a + GetK(k, 7 * t - 1), 21);

        // 9) c ← c ⊕ G5(d ⊞ k[7i])
        c ^= BelTMath.G(d + GetK(k, 7 * t), 5);

        // 10-12) Перестановки a↔b, c↔d, b↔c
        return (b, d, a, c);
    }
}
