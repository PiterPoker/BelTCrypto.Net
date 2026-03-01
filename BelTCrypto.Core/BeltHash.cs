namespace BelTCrypto.Core;

public static class BeltHash
{
    public static byte SubstituteH(byte b) => BelTMath.SubstituteH(b);
    public static uint RotHi(uint value, int bits) => BelTMath.RotHi(value, bits);
    public static BelTBlock BelTBlock(ReadOnlySpan<byte> key) => new(key);
    public static BelTWideBlock BelTWideBlock(BelTBlock block) => new(block);
    public static BelTKeyWrap BelTKeyWrap(BelTWideBlock wideBlock) => new(wideBlock);
}
