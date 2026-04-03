using System.Formats.Asn1;

namespace BelTCrypto.Bign;

public static class BignOids
{
    // Примеры OID из стандарта
    public const string BeltHash = "1.2.112.0.2.0.34.101.31.81";
    public const string BignPubkey = "1.2.112.0.2.0.34.101.45.2.1"; // Пример для l=128

    /// <summary>
    /// Кодирует строковый OID в массив байт (DER encoding).
    /// </summary>
    public static byte[] Encode(string oidValue)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oidValue);
        return writer.Encode();
    }

    /// <summary>
    /// Декодирует OID из байт.
    /// Используем ReadOnlyMemory, так как AsnReader не является ref-структурой.
    /// </summary>
    public static string Decode(ReadOnlyMemory<byte> encodedOid)
    {
        // AsnReader требует Memory для внутреннего хранения буфера
        var reader = new AsnReader(encodedOid, AsnEncodingRules.DER);
        return reader.ReadObjectIdentifier();
    }

    public static string Decode(byte[] encodedOid) => Decode(encodedOid.AsMemory());
}
