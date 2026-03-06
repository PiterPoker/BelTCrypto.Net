using BelTCrypto.Core;
using BelTCrypto.Net;
using System.Security.Cryptography;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTCtrTests
{
    private const CipherMode CTR = (CipherMode)6;

    [Test]
    public void Encrypt_Ctr_TableA15_ReturnsCorrectResult()
    {
        // K = E9DEE72C...
        byte[] key = Convert.FromHexString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        // S = BE329713...
        byte[] s = Convert.FromHexString("BE32971343FC9A48A02A885F194B09A1");
        // X = B194BAC8...
        byte[] x = Convert.FromHexString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");

        // Ожидаемый Y из таблицы А.15
        string expectedY = "52C9AF96FF50F64435FC43DEF56BD797D5B5B1FF79FB41257AB9CDF6E63E81F8F00341473EAE409833622DE05213773A";

        using var algo = new BelTAlgorithm(k => BeltHash.BelTBlock(k));
        algo.Mode = CTR;
        algo.Padding = PaddingMode.None;

        using var encryptor = algo.CreateEncryptor(key, s);
        byte[] actualY = encryptor.TransformFinalBlock(x, 0, x.Length);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }

    [Test]
    public void Decrypt_Ctr_TableA16_PartialBlock_ReturnsCorrectResult()
    {
        // K = 92BD9B1C...
        byte[] key = Convert.FromHexString("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        // S = 7ECDA4D0...
        byte[] s = Convert.FromHexString("7ECDA4D01544AF8CA58450BF66D2E88A");
        // Y = E12BDC1A... (44 байта)
        byte[] y = Convert.FromHexString("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA779");

        // Ожидаемый X из таблицы А.16
        string expectedX = "DF181ED008A20F43DCBBB93650DAD34B389CDEE5826D40E2D4BD80F49A93F5D212F6333166456F169043CC5F";

        using var algo = new BelTAlgorithm(k => BeltHash.BelTBlock(k));
        algo.Mode = CTR;

        // В CTR дешифратор создается точно так же, как шифратор
        using var decryptor = algo.CreateDecryptor(key, s);
        byte[] actualX = decryptor.TransformFinalBlock(y, 0, y.Length);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX));
    }
}