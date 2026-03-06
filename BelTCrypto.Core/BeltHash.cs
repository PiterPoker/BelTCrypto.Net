using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

public static class BeltHash
{
    public static byte SubstituteH(byte b) => BelTMath.SubstituteH(b);
    public static uint RotHi(uint value, int bits) => BelTMath.RotHi(value, bits);
    public static IBelTBlock BelTBlock() => new BelTBlock();
    public static IBelTBlock BelTBlock(ReadOnlySpan<byte> key) => new BelTBlock(key);
    public static IBelTWideBlock BelTWideBlock(IBelTBlock block) => new BelTWideBlock(block);
    public static BelTKeyWrap BelTKeyWrap(IBelTWideBlock wideBlock) => new(wideBlock);
    public static IBelTCompress BelTCompress(IBelTBlock block) => new BelTCompress(block);
    public static IBelTEcbTransform BelTEcbEncryptTransform(IBelTBlock block) => new BelTEcbEncryptTransform(block);
    public static IBelTEcbTransform BelTEcbDecryptTransform(IBelTBlock block) => new BelTEcbDecryptTransform(block);
    public static IBelTCbcTransform BelTCbcEncryptTransform(IBelTBlock block, ReadOnlySpan<byte> iv) => new BelTCbcEncryptTransform(block, iv);
    public static IBelTCbcTransform BelTCbcDecryptTransform(IBelTBlock block, ReadOnlySpan<byte> iv) => new BelTCbcDecryptTransform(block, iv); 
    public static IBelTCfbTransform BelTCfbEncryptTransform(IBelTBlock block, ReadOnlySpan<byte> iv) => new BelTCfbEncryptTransform(block, iv);
    public static IBelTCfbTransform BelTCfbDecryptTransform(IBelTBlock block, ReadOnlySpan<byte> iv) => new BelTCfbDecryptTransform(block, iv);
    public static ICryptoTransform BelTCtrTransform(IBelTBlock block, ReadOnlySpan<byte> iv) => new BelTCtrTransform(block, iv);
}
