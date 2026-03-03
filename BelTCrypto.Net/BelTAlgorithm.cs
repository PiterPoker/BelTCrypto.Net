using System.Security.Cryptography;

namespace BelTCrypto.Net;

public class BelTAlgorithm : SymmetricAlgorithm
{
    public BelTAlgorithm()
    {
        KeySizeValue = 256;
        BlockSizeValue = 128; 
        LegalKeySizesValue = [new KeySizes(128, 256, 64)];
        LegalBlockSizesValue = [new KeySizes(128, 128, 0)];
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        => new BelTTransform(rgbKey, true);

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        => new BelTTransform(rgbKey, false);

    public override void GenerateKey()
    {
        KeyValue = RandomNumberGenerator.GetBytes(KeySizeValue / 8);
    }

    public override void GenerateIV() { /* BelT Wide Block не требует IV в базе */ }
}
