using BelTCrypto.Core;
using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTCompressTests
{
    private IBelTCompress _compressor;

    [SetUp]
    public void Setup()
    {
        _compressor = BelTCompressorFactory.Create();
    }

    [Test]
    public void Compress_ReturnsExpectedValues()
    {
        var x = BelTMath.H[..64];

        var expectedS = new byte[] {
            0x46, 0xFE, 0x74, 0x25, 0xC9, 0xB1, 0x81, 0xEB,
            0x41, 0xDF, 0xEE, 0x3E, 0x72, 0x16, 0x3D, 0x5A
        };
        var expectedY = new byte[] {
            0xED, 0x2F, 0x54, 0x81, 0xD5, 0x93, 0xF4, 0x0D,
            0x87, 0xFC, 0xE3, 0x7D, 0x6B, 0xC1, 0xA2, 0xE1,
            0xB7, 0xD1, 0xA2, 0xCC, 0x97, 0x5C, 0x82, 0xD3,
            0xC0, 0x49, 0x74, 0x88, 0xC9, 0x0D, 0x99, 0xD8
        };

        byte[] actualS = new byte[16];
        byte[] actualY = new byte[32];

        _compressor.Compress(x, actualS, actualY);

        TestContext.Out.WriteLine($"Encrypt S: {BitConverter.ToString(actualS)}");
        TestContext.Out.WriteLine($"Expected S:  {BitConverter.ToString(expectedS)}");
        TestContext.Out.WriteLine($"Encrypt Y: {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y:  {BitConverter.ToString(expectedY)}");

        Assert.Multiple(() =>
        {
            Assert.That(actualS, Is.EqualTo(expectedS), "S не совпадает.");
            Assert.That(actualY, Is.EqualTo(expectedY), "Y не совпадает.");
        });
    }
}
