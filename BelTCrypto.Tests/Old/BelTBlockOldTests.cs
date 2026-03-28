using BelTCrypto.Core.Old;

namespace BelTCrypto.Tests.Old;

[TestFixture]
public class BelTBlockOldTests
{
    [Test]
    public void EncryptBlock_Step1_VerifyInternalVariables()
    {
        // Данные из твоей Таблицы А.1
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE4");
        byte[] expectedY = StringToByteArray("69CCA1C93557C9E3D66BC3E0FA88FA6E");

        var engine = BeltHashOld.BelTBlock(key);
        Span<byte> actualY = stackalloc byte[16];
        engine.Encrypt(x, actualY);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(Convert.ToHexString(expectedY)));
    }

    [Test]
    public void DecryptBlock_StandardVector_ReturnsCorrectPlainText()
    {
        // Данные из Таблицы А.4
        byte[] key = StringToByteArray("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] y = StringToByteArray("E12BDC1AE28257EC703FCCF095EE8DF1");
        byte[] expectedX = StringToByteArray("0DC5300600CAB840B38448E5E993F421");

        var engine = BeltHashOld.BelTBlock(key);
        Span<byte> actualX = stackalloc byte[16];
        engine.Decrypt(y, actualX);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(Convert.ToHexString(expectedX)));
    }

    private static byte[] StringToByteArray(string hex) => [.. Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))];
}
