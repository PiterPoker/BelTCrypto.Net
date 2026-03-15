using BelTCrypto.Core;

namespace BelTCrypto.Tests.Old;

[TestFixture]
public class BelTWideBlockOldTests
{
    [Test]
    public void EncryptWideBlock_384Bit_ReturnsCorrectResult()
    {
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");
        byte[] expectedY = StringToByteArray("49A38EE108D6C742E52B774F00A6EF98B106CBD13EA4FB0680323051BC04DF76E487B055C69BCF541176169F1DC9F6C8");

        byte[] actualY = new byte[x.Length];
        var engine = BeltHash.BelTBlock(key);
        var wideBlock = BeltHash.BelTWideBlock(engine);
        wideBlock.Encrypt(x, actualY);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(Convert.ToHexString(expectedY)));
    }

    [Test]
    public void EncryptWideBlock_256Bit_ReturnsCorrectResult()
    {
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        // Добавил 00 в конце X, чтобы было 32 байта (256 бит)
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B89");
        byte[] expectedY = StringToByteArray("F08EF22DCAA06C81FB12721974221CA7AB82C62856FCF2F9FCA006E019A28F16E5821A51F573594625DBAB8F6A5C94");

        byte[] actualY = new byte[expectedY.Length];
        var engine = BeltHash.BelTBlock(key);
        var wideBlock = BeltHash.BelTWideBlock(engine);

        // Если X короче Y, нам нужно понять логику дополнения в стандарте
        // Пока пробуем как есть (если x.Length == 32)
        wideBlock.Encrypt(x, actualY);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(Convert.ToHexString(expectedY)));
    }

    [Test]
    public void DecryptWideBlock_384Bit_ReturnsCorrectResult()
    {
        // Таблица А.7 (Первый вектор - 48 байт)
        byte[] key = StringToByteArray("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] y = StringToByteArray("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799EB23D31");
        byte[] expectedX = StringToByteArray("92632EE0C21AD9E09A39343E5C07DAA4889B03F2E6847EB152EC99F7A4D9F154B5EF68D8E4A39E567153DE13D72254EE");

        byte[] actualX = new byte[y.Length];
        var engine = BeltHash.BelTBlock(key);
        var wideBlock = BeltHash.BelTWideBlock(engine);

        wideBlock.Decrypt(y, actualX);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(Convert.ToHexString(expectedX)));
    }

    [Test]
    public void DecryptWideBlock_PartialBlock_ReturnsCorrectResult()
    {
        // Таблица А.7 (Второй вектор - 33 байта)
        byte[] key = StringToByteArray("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] y = StringToByteArray("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B");
        byte[] expectedX = StringToByteArray("DF3F882230BAAFFC92F05660321172310E3CB2182681EF43102E67175E177BD75E93E4E8");

        byte[] actualX = new byte[y.Length];
        var engine = BeltHash.BelTBlock(key);
        var wideBlock = BeltHash.BelTWideBlock(engine);

        wideBlock.Decrypt(y, actualX);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(Convert.ToHexString(expectedX)));
    }

    private static byte[] StringToByteArray(string hex) => [.. Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))];
}
