using BelTCrypto.Core.Interfaces;
using BelTCrypto.Core.Interfaces.Old;
using BelTCrypto.Core.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

public static class BeltHash
{
    public static byte SubstituteH(byte b) => BelTMathOld.SubstituteH(b);
    public static uint RotHi(uint value, int bits) => BelTMathOld.RotHi(value, bits);
    public static void MultiplyGF128(Span<byte> t, ReadOnlySpan<byte> r) => BelTMathOld.MultiplyGF128(t, r);
    public static IBelTBlockOld BelTBlock() => new BelTBlockOld();
    public static IBelTBlockOld BelTBlock(ReadOnlySpan<byte> key) => new BelTBlockOld(key);
    public static IBelTWideBlockOld BelTWideBlock(IBelTBlockOld block) => new BelTWideBlockOld(block);
    public static IBelTCompressOld BelTCompress(IBelTBlockOld block) => new BelTCompressOld(block);
    public static IBelTEcbTransform BelTEcbEncryptTransform(IBelTBlockOld block) => new BelTEcbEncryptTransform(block);
    public static IBelTEcbTransform BelTEcbDecryptTransform(IBelTBlockOld block) => new BelTEcbDecryptTransform(block);
    public static IBelTCbcTransform BelTCbcEncryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCbcEncryptTransform(block, iv);
    public static IBelTCbcTransform BelTCbcDecryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCbcDecryptTransform(block, iv); 
    public static IBelTCfbTransform BelTCfbEncryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCfbEncryptTransform(block, iv);
    public static IBelTCfbTransform BelTCfbDecryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCfbDecryptTransform(block, iv);
    public static IBelTCrtTransform BelTCtrTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv) => new BelTCtrTransform(block, iv);
    public static IBelTMac BelTMac(IBelTBlockOld block) => new BelTMac(block);

    public static IBelTAead BelTDwp(IBelTBlockOld block)=> new BelTDwp(block);
}
