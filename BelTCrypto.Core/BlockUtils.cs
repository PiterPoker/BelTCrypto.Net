using System.Buffers.Binary;
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
}