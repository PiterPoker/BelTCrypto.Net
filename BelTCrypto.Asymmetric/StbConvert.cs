namespace BelTCrypto.Bign;

public static class StbConvert
{
    /// <summary>
    /// Преобразует строку hex-символов в массив байт согласно СТБ 34.101.45.
    /// Стандарт подразумевает, что "B1" в строке — это байт 0xB1 (1011 0001).
    /// </summary>
    public static byte[] FromHexString(string hex)
    {
        // Убираем пробелы, которые часто встречаются в тексте стандарта
        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");

        if (hex.Length % 2 != 0)
            throw new ArgumentException("Hex string must have an even length");

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    /// <summary>
    /// Выводит байты в формате hex-строки как в стандарте.
    /// </summary>
    public static string ToHexString(ReadOnlySpan<byte> data)
    {
        return Convert.ToHexString(data.ToArray());
    }
}
