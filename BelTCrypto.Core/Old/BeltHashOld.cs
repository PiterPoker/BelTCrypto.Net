using BelTCrypto.Core.Interfaces.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Old;

public static class BeltHashOld
{
    public static byte SubstituteH(byte b) => BelTMathOld.SubstituteH(b);
    public static uint RotHi(uint value, int bits) => BelTMathOld.RotHi(value, bits);
    public static void MultiplyGF128(Span<byte> t, ReadOnlySpan<byte> r) => BelTMathOld.MultiplyGF128(t, r);
    public static IBelTBlockOld BelTBlock() => new BelTBlockOld();
    public static IBelTBlockOld BelTBlock(ReadOnlySpan<byte> key) => new BelTBlockOld(key);
    public static IBelTWideBlockOld BelTWideBlock(IBelTBlockOld block) => new BelTWideBlockOld(block);
    public static IBelTCompressOld BelTCompress(IBelTBlockOld block) => new BelTCompressOld(block);
    public static IBelTEcbTransformOld BelTEcbEncryptTransform(IBelTBlockOld block) => new BelTEcbEncryptTransformOld(block);
    public static IBelTEcbTransformOld BelTEcbDecryptTransform(IBelTBlockOld block) => new BelTEcbDecryptTransformOld(block);
    public static IBelTCbcOldTransform BelTCbcEncryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCbcEncryptOldTransform(block, iv);
    public static IBelTCbcOldTransform BelTCbcDecryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCbcDecryptOldTransform(block, iv); 
    public static IBelTCfbOldTransform BelTCfbEncryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCfbEncryptOldTransform(block, iv);
    public static IBelTCfbOldTransform BelTCfbDecryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCfbDecryptOldTransform(block, iv);
    public static IBelTCrtOldTransform BelTCtrTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCtrOldTransform(block, iv);
    public static IBelTMacOld BelTMac(IBelTBlockOld block) => new BelTMacOld(block);

    public static IBelTAeadOld BelTDwp(IBelTBlockOld block)=> new BelTDwpOld(block);
}
