using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace BelTCrypto.Core;

public sealed class BelTBlock
{
    private readonly uint[] _roundKeys = new uint[8];

    public BelTBlock(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("Key must be 256 bits.");

        for (int i = 0; i < 8; i++)
        {
            _roundKeys[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        }
    }

    public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        // 1. Разбиение на слова a, b, c, d (X1, X2, X3, X4) - Little Endian
        uint a = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(0, 4));
        uint b = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4, 4));
        uint c = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(8, 4));
        uint d = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(12, 4));

        for (int i = 1; i <= 8; i++)
        {
            // В BelT раундовые ключи k[1]..k[7] в каждом такте одни и те же? 
            // Нет, k[i] = K_{((i-1) mod 8) + 1}. Но внутри такта используются разные K_j.
            // Согласно стандарту (п. 6.1.3), в такте i используются ключи:
            // k[1]=K1, k[2]=K2 ... но они смещаются? 
            // Судя по твоей таблице А.3, используются конкретные индексы k[1]..k[7].

            // ВАЖНО: В каждом такте i ключи k[j] вычисляются как K_((7(i-1) + j-1) mod 8 + 1)
            uint k1 = GetKey(i, 1);
            uint k2 = GetKey(i, 2);
            uint k3 = GetKey(i, 3);
            uint k4 = GetKey(i, 4);
            uint k5 = GetKey(i, 5);
            uint k6 = GetKey(i, 6);
            uint k7 = GetKey(i, 7);

            // 1) b = b ^ G5(a + k1)
            b ^= BelTMath.G(a + k1, 5);
            // 2) c = c ^ G21(d + k2)
            c ^= BelTMath.G(d + k2, 21);
            // 3) a = a - G13(b + k3)
            a -= BelTMath.G(b + k3, 13);
            // 4) e = G21(b + c + k4) ^ i
            uint e = BelTMath.G(b + c + k4, 21) ^ (uint)i;
            // 5) b = b + e
            b += e;
            // 6) c = c - e
            c -= e;
            // 7) d = d + G13(c + k5)
            d += BelTMath.G(c + k5, 13);
            // 8) b = b ^ G21(a + k6)
            b ^= BelTMath.G(a + k6, 21);
            // 9) c = c ^ G5(d + k7)
            c ^= BelTMath.G(d + k7, 5);

            // 10-12) Перестановки a <-> b, c <-> d, b <-> c
            // Итог: a_next = b, b_next = d, c_next = a, d_next = c
            uint nextA = b;
            uint nextB = d;
            uint nextC = a;
            uint nextD = c;

            a = nextA; b = nextB; c = nextC; d = nextD;
        }

        // Финальная сборка Y. По таблице А.2 для i=8:
        // a=D66BC3E0, b=69CCA1C9, c=FA88FA6E, d=3557C9E3
        // Y должен быть: 69CCA1C9 3557C9E3 D66BC3E0 FA88FA6E
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(0, 4), b);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4, 4), d);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(8, 4), a);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(12, 4), c);
    }

    public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        // 1. Разбиение входного шифртекста Y на слова (b, d, a, c)
        // ВНИМАНИЕ: При шифровании мы записывали в output (b, d, a, c). 
        // Значит при чтении для расшифрования:
        uint b = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(0, 4));
        uint d = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4, 4));
        uint a = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(8, 4));
        uint c = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(12, 4));

        // 2. Выполнение 8 тактов в обратном порядке
        for (int i = 8; i >= 1; i--)
        {
            // Ключи для такта i те же самые
            uint k1 = GetKey(i, 1);
            uint k2 = GetKey(i, 2);
            uint k3 = GetKey(i, 3);
            uint k4 = GetKey(i, 4);
            uint k5 = GetKey(i, 5);
            uint k6 = GetKey(i, 6);
            uint k7 = GetKey(i, 7);

            // Инверсия финальных перестановок такта: (b, d, a, c) -> (a, b, c, d)
            // При шифровании было: nextA=b, nextB=d, nextC=a, nextD=c.
            // Значит обратное:
            uint prevA = c;
            uint prevB = a;
            uint prevC = d;
            uint prevD = b;
            a = prevA; b = prevB; c = prevC; d = prevD;

            // 9) c = c ^ G5(d + k7)
            c ^= BelTMath.G(d + k7, 5);
            // 8) b = b ^ G21(a + k6)
            b ^= BelTMath.G(a + k6, 21);
            // 7) d = d - G13(c + k5)
            d -= BelTMath.G(c + k5, 13);
            // 6) c = c + e
            // 5) b = b - e
            // 4) e = G21(b + c + k4) ^ i
            // Чтобы сделать шаги 5 и 6, нам сначала нужно вычислить e.
            // Но e зависит от b и c после шагов 5 и 6? Нет. 
            // В оригинале: b_new = b_old + e, c_new = c_old - e.
            // Тогда (b_new + c_new) = (b_old + e + c_old - e) = b_old + c_old.
            // Сумма b + c инвариантна относительно e!
            uint e = BelTMath.G(b + c + k4, 21) ^ (uint)i;
            c += e; // c_old = c_new + e
            b -= e; // b_old = b_new - e

            // 3) a = a + G13(b + k3)
            a += BelTMath.G(b + k3, 13);
            // 2) c = c ^ G21(d + k2)
            c ^= BelTMath.G(d + k2, 21);
            // 1) b = b ^ G5(a + k1)
            b ^= BelTMath.G(a + k1, 5);
        }

        // 3. Сборка результата X = (a, b, c, d)
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(0, 4), a);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4, 4), b);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(8, 4), c);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(12, 4), d);
    }

    // Метод для получения ключа согласно расписанию (п. 7.1.1)
    private uint GetKey(int step, int j)
    {
        int index = (7 * (step - 1) + j - 1) % 8;
        return _roundKeys[index];
    }
}