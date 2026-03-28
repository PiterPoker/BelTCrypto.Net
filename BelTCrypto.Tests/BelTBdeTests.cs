using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTBdeTests
{
    private IDiskEncryption _bde;

    [SetUp]
    public void Setup() => _bde = BelTDiskEncryptionFactory.Create(BelTDiskEncryptionFactory.BeltDiskScheme.Bde);

    [Test]
    public void Bde_TableA24_Encrypt()
    {
        // X = B194BAC8... (48 байт из таблицы H)
        var x = Core.BelTMath.H[..48];

        // K = E9DEE72C... (32 байта из таблицы H, смещение 128)
        var k = Core.BelTMath.H[128..160];

        // S = BE329713... (16 байт из таблицы H, смещение 192)
        var s = Core.BelTMath.H[192..208];

        var expectedY = new byte[]
        {
              0xE9, 0xCA, 0xB3, 0x2D, 0x87, 0x9C, 0xC5, 0x0C,
              0x10, 0x37, 0x8E, 0xB0, 0x7C, 0x10, 0xF2, 0x63,
              0x07, 0x25, 0x7E, 0x2D, 0xBE, 0x2B, 0x85, 0x4C, 
              0xBC, 0x9F, 0x38, 0x28, 0x2D, 0x59, 0xD6, 0xA7,
              0x7F, 0x95, 0x20, 0x01, 0xC5, 0xD1, 0x24, 0x4F,
              0x53, 0x21, 0x0A, 0x27, 0xC2, 0x16, 0xD4, 0xBB
        };

        var actualY = new byte[x.Length];
        _bde.Encrypt(x, k, s, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "BDE Encrypt Table A.24 failed");
    }

    [Test]
    public void Bde_TableA25_Decrypt()
    {
        var y = Core.BelTMath.H[64..112];
        var k = Core.BelTMath.H[160..192];
        var s = Core.BelTMath.H[208..224];
        var expectedX = new byte[] 
        {
             0x70, 0x41, 0xBC, 0x22, 0x63, 0x52, 0xC7, 0x06,
             0xD0, 0x0E, 0xA8, 0xEF, 0x23, 0xCF, 0xE4, 0x6A,
             0xFA, 0xE1, 0x18, 0x57, 0x7D, 0x03, 0x7F, 0xAC,
             0xDC, 0x36, 0xE4, 0xEC, 0xC1, 0xF6, 0x57, 0x46,
             0x09, 0xF2, 0x36, 0x94, 0x3F, 0xB8, 0x09, 0xE1,
             0xBE, 0xE4, 0xA1, 0xC6, 0x86, 0xC1, 0x3A, 0xCC
        };


        var actualX = new byte[y.Length];
        _bde.Decrypt(y, k, s, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        Assert.That(actualX, Is.EqualTo(expectedX.ToArray()), "BDE Decrypt Table A.25 failed");
    }
}