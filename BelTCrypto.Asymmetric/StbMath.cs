using System.Numerics;

namespace BelTCrypto.Bign;

public static class StbMath
{
    /// <summary>
    /// Преобразование октетов в BigInteger согласно разделу 5.1 (Little-endian).
    /// </summary>
    public static BigInteger ToInteger(ReadOnlySpan<byte> bytes)
    {
        // В .NET BigInteger(ReadOnlySpan<byte> value, bool isUnsigned, bool isBigEndian)
        // Для СТБ: isUnsigned = true, isBigEndian = false
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
    }

    /// <summary>
    /// Преобразование BigInteger обратно в октеты заданной длины.
    /// </summary>
    public static byte[] ToBytes(BigInteger value, int length)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);

        if (bytes.Length == length) return bytes;

        // Дополняем нулями или обрезаем (хотя обрезка — признак ошибки в логике)
        byte[] fixedBytes = new byte[length];
        Array.Copy(bytes, fixedBytes, Math.Min(bytes.Length, length));
        return fixedBytes;
    }
}
