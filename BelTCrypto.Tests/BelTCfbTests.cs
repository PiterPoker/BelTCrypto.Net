using BelTCrypto.Core;
using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTCfbTests
{
    private IBelTCfb _cfb;

    [SetUp]
    public void Setup()
    {
        _cfb = BelTCfbFactory.Create();
    }

    [Test]
    public void Encrypt_TableA13_Success()
    {
        // Данные из таблицы А.13
        var k = Core.BelTMath.H[128..160];
        var s = Core.BelTMath.H[192..208];
        var x = Core.BelTMath.H[..48];

        var expectedY = new byte[]
        {
            0xC3, 0x1E, 0x49, 0x0A, 0x90, 0xEF, 0xA3, 0x74, 
            0x62, 0x6C, 0xC9, 0x9E, 0x4B, 0x7B, 0x85, 0x40, 
            0xA6, 0xE4, 0x86, 0x85, 0x46, 0x4A, 0x5A, 0x06, 
            0x84, 0x9C, 0x9C, 0xA7, 0x69, 0xA1, 0xB0, 0xAE,
            0x55, 0xC2, 0xCC, 0x59, 0x39, 0x30, 0x3E, 0xC8, 
            0x32, 0xDD, 0x2F, 0xE1, 0x6C, 0x8E, 0x5A, 0x1B
        };

        var actualY = new byte[x.Length];
        _cfb.Encrypt(x, k, s, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");
        Assert.That(actualY, Is.EqualTo(expectedY), "CFB Encryption failed (Table A.13)");
    }

    [Test]
    public void Decrypt_TableA13_Success()
    {
        var k = Core.BelTMath.H[160..192];
        var s = Core.BelTMath.H[208..224];
        var y = Core.BelTMath.H[64..112];

        var expectedX = new byte[]
        {
            0xFA, 0x9D, 0x10, 0x7A, 0x86, 0xF3, 0x75, 0xEE, 
            0x65, 0xCD, 0x1D, 0xB8, 0x81, 0x22, 0x4B, 0xD0, 
            0x16, 0xAF, 0xF8, 0x14, 0x93, 0x8E, 0xD3, 0x9B, 
            0x33, 0x61, 0xAB, 0xB0, 0xBF, 0x08, 0x51, 0xB6,
            0x52, 0x24, 0x4E, 0xB0, 0x68, 0x42, 0xDD, 0x4C, 
            0x94, 0xAA, 0x45, 0x00, 0x77, 0x4E, 0x40, 0xBB
        };

        var actualX = new byte[y.Length];
        _cfb.Decrypt(y, k, s, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");
        Assert.That(actualX, Is.EqualTo(expectedX), "CFB Decryption failed (Table A.13)");
    }
}
