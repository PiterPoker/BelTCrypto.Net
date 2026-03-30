using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("BelTCrypto.Tests")]
namespace BelTCrypto.Core;


internal static class BlockUtils
{
    internal static (uint a, uint b, uint c, uint d) ReadUInt32LittleEndian(ReadOnlySpan<byte> x)
    {
        if (x.Length != 16) throw new ArgumentException("Блок должен быть 128 бит.");

        return (BinaryPrimitives.ReadUInt32LittleEndian(x[0..4])
            , BinaryPrimitives.ReadUInt32LittleEndian(x[4..8])
            , BinaryPrimitives.ReadUInt32LittleEndian(x[8..12])
            , BinaryPrimitives.ReadUInt32LittleEndian(x[12..16]));
    }

    internal static void WriteUInt32LittleEndian(uint a, uint b, uint c, uint d, Span<byte> y)
    {
        if (y.Length != 16) throw new ArgumentException("Блок должен быть 128 бит.");

        BinaryPrimitives.WriteUInt32LittleEndian(y[0..4], a);
        BinaryPrimitives.WriteUInt32LittleEndian(y[4..8], b);
        BinaryPrimitives.WriteUInt32LittleEndian(y[8..12], c);
        BinaryPrimitives.WriteUInt32LittleEndian(y[12..16], d);
    }

    internal static void Str2Bin(ReadOnlySpan<ushort> u, int m, Span<byte> output)
    {
        BigInteger value = 0;
        BigInteger mBI = m;
        BigInteger power = 1;

        // u[0] - младший символ, вес m^0
        for (int i = 0; i < u.Length; i++)
        {
            value += (BigInteger)u[i] * power;
            power *= mBI;
        }

        output.Clear();
        // Пишем как Little-Endian. Это заполнит output[0], output[1]... 
        // Если число меньше bj, остаток буфера останется нулями (правильный padding).
        value.TryWriteBytes(output, out _, isUnsigned: true, isBigEndian: false);
    }

    internal static void Bin2Str(ReadOnlySpan<byte> t, int m, int nj, Span<ushort> output)
    {
        // Читаем как Little-Endian.
        BigInteger value = new(t, isUnsigned: true, isBigEndian: false);
        BigInteger mBI = m;

        for (int i = 0; i < nj; i++)
        {
            // Первый остаток - это всегда коэффициент при m^0 (т.е. первый символ)
            value = BigInteger.DivRem(value, mBI, out BigInteger remainder);
            output[i] = (ushort)remainder;
        }
    }
}