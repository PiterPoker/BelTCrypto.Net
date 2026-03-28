using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTSdeTests
{
    private IDiskEncryption _sde;

    [SetUp]
    public void Setup() => _sde = BelTDiskEncryptionFactory.Create(BelTDiskEncryptionFactory.BeltDiskScheme.Sde);

    [Test]
    public void Sde_TableA24_Encrypt()
    {
        // X = B194BAC8... (48 байт из таблицы H)
        var x = Core.BelTMath.H[..48];

        // K = E9DEE72C... (32 байта из таблицы H, смещение 128)
        var k = Core.BelTMath.H[128..160];

        // S = BE329713... (16 байт из таблицы H, смещение 192)
        var s = Core.BelTMath.H[192..208];

        var expectedY = new byte[]
        {
              0x1F, 0xCB, 0xB0, 0x18, 0x52, 0x00, 0x3D, 0x60,
              0xB6, 0x60, 0x24, 0xC5, 0x08, 0x60, 0x8B, 0xAA,
              0x2C, 0x21, 0xAF, 0x1E, 0x88, 0x4C, 0xF3, 0x11,
              0x54, 0xD3, 0x07, 0x7D, 0x46, 0x43, 0xCF, 0x22,
              0x49, 0xEB, 0x2F, 0x5A, 0x68, 0xE4, 0xBA, 0x01,
              0x9D, 0x90, 0x21, 0x1A, 0x81, 0xD6, 0x90, 0xD9
        };

        var actualY = new byte[x.Length];
        _sde.Encrypt(x, k, s, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "SDE Encrypt Table A.24 failed");
    }

    [Test]
    public void Sde_TableA25_Decrypt()
    {
        var y = Core.BelTMath.H[64..112];
        var k = Core.BelTMath.H[160..192];
        var s = Core.BelTMath.H[208..224];

        var expectedX = new byte[]
        {
             0xE9, 0xFD, 0xF3, 0xF7, 0x88, 0x65, 0x73, 0x32,
             0xE6, 0xC4, 0x6F, 0xCF, 0x52, 0x51, 0xB8, 0xA6,
             0xD4, 0x35, 0x43, 0xA9, 0x3E, 0x32, 0x33, 0x83, 
             0x7D, 0xB1, 0x57, 0x11, 0x83, 0xA6, 0xEF, 0x4D,
             0x7F, 0xEB, 0x5C, 0xDF, 0x99, 0x9E, 0x1A, 0x3F,
             0x51, 0xA5, 0xA3, 0x38, 0x1B, 0xEB, 0x7F, 0xA5
        };

        var actualX = new byte[y.Length];
        _sde.Decrypt(y, k, s, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        Assert.That(actualX, Is.EqualTo(expectedX), "SDE Decrypt Table A.25 failed");
    }
}