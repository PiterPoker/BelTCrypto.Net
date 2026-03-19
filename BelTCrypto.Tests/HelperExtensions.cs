using System.Buffers.Binary;

namespace BelTCrypto.Tests;


public static class HelperExtensions
{
    public static uint ToRevert(this uint hex)
    {
        return BinaryPrimitives.ReverseEndianness(hex);
    }
}

