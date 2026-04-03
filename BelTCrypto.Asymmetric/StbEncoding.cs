using System.Numerics;

namespace BelTCrypto.Bign;

public static class StbEncoding
{
    /// <summary>
    /// Преобразование последовательности октетов в число согласно СТБ 34.101.45 (п. 4.2.2).
    /// Используется Little-Endian: первый байт - младший.
    /// </summary>
    public static BigInteger OctetsToInteger(ReadOnlySpan<byte> octets)
    {
        if (octets.IsEmpty) return BigInteger.Zero;

        // В .NET BigInteger из Span по умолчанию ожидает Little-Endian.
        // Параметр isUnsigned: true критически важен, чтобы старший бит последнего байта 
        // не интерпретировался как знаковый (для положительных чисел).
        return new BigInteger(octets, isUnsigned: true, isBigEndian: false);
    }

    /// <summary>
    /// Преобразование числа в последовательность октетов заданной длины L.
    /// </summary>
    public static void IntegerToOctets(BigInteger value, Span<byte> destination)
    {
        if (!value.TryWriteBytes(destination, out int bytesWritten, isUnsigned: true, isBigEndian: false))
        {
            throw new ArgumentException("Размер буфера недостаточен для записи числа.");
        }

        // Если число заняло меньше места, чем размер буфера L, 
        // остаток уже заполнен нулями (поскольку TryWriteBytes затирает Span),
        // что соответствует логике Little-Endian (дополнение старшими нулями в конце).
    }
}
