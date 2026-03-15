using BelTCrypto.Core;

namespace BelTCrypto.Tests.Old;

[TestFixture]
public class BelTCompressOldTests
{
    [Test]
    public void Compress_StandardVector_ReturnsCorrectResult()
    {
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B5CB0C0FF33C356B835C405AED8E07F99");
        string expectedS = "46FE7425C9B181EB41DFEE3E72163D5A";
        string expectedY = "ED2F5481D593F40D87FCE37D6BC1A2E1B7D1A2CC975C82D3C0497488C90D99D8";

        var engine = BeltHash.BelTBlock();
        var beltCompress = BeltHash.BelTCompress(engine);
        var (S, Y) = beltCompress.Compress(x);

        Assert.Multiple(() =>
        {
            Assert.That(Convert.ToHexString(S), Is.EqualTo(expectedS));
            Assert.That(Convert.ToHexString(Y), Is.EqualTo(expectedY));
        });
    }

    private static byte[] StringToByteArray(string hex) => [.. Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))];
}
