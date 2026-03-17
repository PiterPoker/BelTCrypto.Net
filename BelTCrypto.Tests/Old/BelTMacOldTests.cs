using BelTCrypto.Net;
using NUnit.Framework;

namespace BelTCrypto.Tests.Old;

[TestFixture]
public class BelTMacOldTests
{
    // Общий ключ для обоих тестов
    private readonly byte[] _key = Convert.FromHexString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");

    [Test]
    public void Mac_TableA17_Case1_PartialBlock()
    {
        // X = B194BAC8 0A08F53B 366D008E 58 (13 байт)
        byte[] x = Convert.FromHexString("B194BAC80A08F53B366D008E58");

        // Ожидаемый Y: 7260DA60 138F96C9
        // Внимание: Convert.ToHexString выдаст байты в том порядке, в котором они лежат в массиве.
        // Если в массиве [0x72, 0x60, ...], то строка будет "7260DA60138F96C9"
        string expectedY = "7260DA60138F96C9";

        using var mac = new BelTMac(_key);
        byte[] actualY = mac.ComputeHash(x);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }

    [Test]
    public void Mac_TableA17_Case2_FullBlocks()
    {
        // X = 48 байт (3 полных блока по 16 байт)
        byte[] x = Convert.FromHexString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");

        // Ожидаемый Y: 2DAB5977 1B4B16D0
        string expectedY = "2DAB59771B4B16D0";

        using var mac = new BelTMac(_key);
        byte[] actualY = mac.ComputeHash(x);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }
}