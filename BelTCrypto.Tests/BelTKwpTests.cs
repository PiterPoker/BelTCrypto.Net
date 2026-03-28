using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTKwpTests
{
    private IBelTKwp _kwp;

    [SetUp]
    public void Setup() => _kwp = BelTKwpFactory.Create();

    [Test]
    public void Protect_TableA21_KeyWrap()
    {
        // Данные из Таблицы А.21
        var x = Core.BelTMath.H[..32];
        var i = Core.BelTMath.H[32..48];
        var k = Core.BelTMath.H[128..160];

        var expectedY = new byte[] {
            0x49, 0xA3, 0x8E, 0xE1, 0x08, 0xD6, 0xC7, 0x42, 
            0xE5, 0x2B, 0x77, 0x4F, 0x00, 0xA6, 0xEF, 0x98, 
            0xB1, 0x06, 0xCB, 0xD1, 0x3E, 0xA4, 0xFB, 0x06, 
            0x80, 0x32, 0x30, 0x51, 0xBC, 0x04, 0xDF, 0x76,
            0xE4, 0x87, 0xB0, 0x55, 0xC6, 0x9B, 0xCF, 0x54, 
            0x11, 0x76, 0x16, 0x9F, 0x1D, 0xC9, 0xF6, 0xC8
        };

        var actualY = new byte[x.Length + 16];
        _kwp.Protect(x, i, k, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "KWP Protect (Table A.21) failed");
    }

    [Test]
    public void Unprotect_TableA22_KeyUnwrap()
    {
        // Данные из Таблицы А.22
        var y = Core.BelTMath.H[64..112];
        var i = new byte[] {
            0xB5, 0xEF, 0x68, 0xD8, 0xE4, 0xA3, 0x9E, 0x56, 
            0x71, 0x53, 0xDE, 0x13, 0xD7, 0x22, 0x54, 0xEE
        };
        var k = Core.BelTMath.H[160..192];

        var expectedX = new byte[] {
            0x92, 0x63, 0x2E, 0xE0, 0xC2, 0x1A, 0xD9, 0xE0, 
            0x9A, 0x39, 0x34, 0x3E, 0x5C, 0x07, 0xDA, 0xA4, 
            0x88, 0x9B, 0x03, 0xF2, 0xE6, 0x84, 0x7E, 0xB1, 
            0x52, 0xEC, 0x99, 0xF7, 0xA4, 0xD9, 0xF1, 0x54
        };

        var actualX = new byte[y.Length - 16];
        bool isValid = _kwp.Unprotect(y, i, k, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True, "KWP Unprotect integrity check failed");
            Assert.That(actualX, Is.EqualTo(expectedX), "KWP Unprotect (Table A.22) data mismatch");
        });
    }
}
