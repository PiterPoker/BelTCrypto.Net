using BelTCrypto.Core;
using BelTCrypto.Core.Interfaces;
using NUnit.Framework;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTEcbTests
{
    private static byte[] StringToByteArray(string hex) =>
        [.. Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))];

    [Test]
    public void Encrypt_SimpleReplacement_FullBlocks_ReturnsCorrectResult()
    {
        // Данные из первой части Таблицы А.9 (48 байт / 3 блока)
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");
        string expectedY = "69CCA1C93557C9E3D66BC3E0FA88FA6E5F23102EF109710775017F73806DA9DC46FB2ED2CE771F26DCB5E5D1569F9AB0";

        var block = BeltHash.BelTBlock(key);
        var ecb = BeltHash.BelTEcb(block);

        byte[] actualY = new byte[x.Length];
        ecb.Encrypt(x, actualY);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }

    [Test]
    public void Encrypt_SimpleReplacement_PartialBlock_ReturnsCorrectResult()
    {
        // Данные из второй части Таблицы А.9 (44 байта)
        // Тут работает логика 3.2 и 3.3 стандарта (захват хвоста r)
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B89");
        string expectedY = "69CCA1C93557C9E3D66BC3E0FA88FA6E36F00CFED6D1CA1498C12798F4BEB2075F23102EF109710775017F73806DA9";

        var block = BeltHash.BelTBlock(key);
        var ecb = BeltHash.BelTEcb(block);

        byte[] actualY = new byte[x.Length];
        ecb.Encrypt(x, actualY);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }

    [Test]
    public void Decrypt_TableA10_FullBlocks_ReturnsCorrectResult()
    {
        // Данные из первой части Таблицы А.10 (48 байт)
        byte[] key = StringToByteArray("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] y = StringToByteArray("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799EB23D31");
        string expectedX = "0DC5300600CAB840B38448E5E993F421E55A239F2AB5C5D5FDB6E81B40938E2A54120CA3E6E19C7AD750FC3531DAEAB7";

        var block = BeltHash.BelTBlock(key);
        var ecb = BeltHash.BelTEcb(block);

        byte[] actualX = new byte[y.Length];
        ecb.Decrypt(y, actualX);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX));
    }

    [Test]
    public void Decrypt_TableA10_PartialBlock_ReturnsCorrectResult()
    {
        // Данные из второй части Таблицы А.10 (36 байт)
        byte[] key = StringToByteArray("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] y = StringToByteArray("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B");
        string expectedX = "0DC5300600CAB840B38448E5E993F4215780A6E2B69EAFBB258726D7B6718523E55A239F";

        var block = BeltHash.BelTBlock(key);
        var ecb = BeltHash.BelTEcb(block);

        byte[] actualX = new byte[y.Length];
        ecb.Decrypt(y, actualX);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX));
    }
}