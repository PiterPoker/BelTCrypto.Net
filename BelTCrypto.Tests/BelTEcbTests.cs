using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTEcbTests
{
    private IBelTEcb _ecb;

    [SetUp]
    public void Setup() => _ecb = BelTEcbFactory.Create();

    [Test]
    public void Encrypt_TableA9_FullBlocks()
    {
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..48];
        var expectedY = new byte[]
        {
            0x69, 0xCC, 0xA1, 0xC9, 0x35, 0x57, 0xC9, 0xE3,
            0xD6, 0x6B, 0xC3, 0xE0, 0xFA, 0x88, 0xFA, 0x6E,
            0x5F, 0x23, 0x10, 0x2E, 0xF1, 0x09, 0x71, 0x07,
            0x75, 0x01, 0x7F, 0x73, 0x80, 0x6D, 0xA9, 0xDC,
            0x46, 0xFB, 0x2E, 0xD2, 0xCE, 0x77, 0x1F, 0x26,
            0xDC, 0xB5, 0xE5, 0xD1, 0x56, 0x9F, 0x9A, 0xB0
        };

        var actualY = new byte[x.Length];
        _ecb.Encrypt(x, k, actualY);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "ECB Full Blocks failed");
    }

    [Test]
    public void Encrypt_TableA9_PartialBlock()
    {
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..47];
        var expectedY = new byte[]
        {
            0x69, 0xCC, 0xA1, 0xC9, 0x35, 0x57, 0xC9, 0xE3,
            0xD6, 0x6B, 0xC3, 0xE0, 0xFA, 0x88, 0xFA, 0x6E,
            0x36, 0xF0, 0x0C, 0xFE, 0xD6, 0xD1, 0xCA, 0x14,
            0x98, 0xC1, 0x27, 0x98, 0xF4, 0xBE, 0xB2, 0x07,
            0x5F, 0x23, 0x10, 0x2E, 0xF1, 0x09, 0x71, 0x07,
            0x75, 0x01, 0x7F, 0x73, 0x80, 0x6D, 0xA9
        };

        var actualY = new byte[x.Length];
        _ecb.Encrypt(x, k, actualY);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "ECB Full Blocks failed");
    }

    [Test]
    public void Decrypt_TableA10_FullBlocks()
    {
        // Данные из Таблицы А.10 (полные блоки)
        var k = Core.BelTMath.H[160..192];
        var y = Core.BelTMath.H[64..112];
        var expectedX = new byte[]
        {
            0x0D, 0xC5, 0x30, 0x06, 0x00, 0xCA, 0xB8, 0x40,
            0xB3, 0x84, 0x48, 0xE5, 0xE9, 0x93, 0xF4, 0x21,
            0xE5, 0x5A, 0x23, 0x9F, 0x2A, 0xB5, 0xC5, 0xD5,
            0xFD, 0xB6, 0xE8, 0x1B, 0x40, 0x93, 0x8E, 0x2A,
            0x54, 0x12, 0x0C, 0xA3, 0xE6, 0xE1, 0x9C, 0x7A,
            0xD7, 0x50, 0xFC, 0x35, 0x31, 0xDA, 0xEA, 0xB7
        };

        var actualX = new byte[y.Length];
        _ecb.Decrypt(y, k, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        Assert.That(actualX, Is.EqualTo(expectedX), "ECB Decrypt Full Blocks failed (Table A.10)");
    }

    [Test]
    public void Decrypt_TableA10_PartialBlock()
    {
        // Данные из Таблицы А.10 (неполный блок, 41 байт)
        var k = Core.BelTMath.H[160..192];
        var y = Core.BelTMath.H[64..100];
        var expectedX = new byte[]
        {
            0x0D, 0xC5, 0x30, 0x06, 0x00, 0xCA, 0xB8, 0x40,
            0xB3, 0x84, 0x48, 0xE5, 0xE9, 0x93, 0xF4, 0x21,
            0x57, 0x80, 0xA6, 0xE2, 0xB6, 0x9E, 0xAF, 0xBB,
            0x25, 0x87, 0x26, 0xD7, 0xB6, 0x71, 0x85, 0x23,
            0xE5, 0x5A, 0x23, 0x9F
        };

        var actualX = new byte[y.Length];
        _ecb.Decrypt(y, k, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        Assert.That(actualX, Is.EqualTo(expectedX), "ECB Decrypt Partial Block failed (Table A.10)");
    }
}