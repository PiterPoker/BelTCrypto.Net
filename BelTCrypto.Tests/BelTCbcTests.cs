using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTCbcTests
{
    private IBelTCbc _cbc;

    [SetUp]
    public void Setup() => _cbc = BelTCbcFactory.Create();

    [Test]
    public void Encrypt_TableA11_FullBlocks()
    {
        // Данные из таблицы А.11 (48 байт)
        var k = Core.BelTMath.H[128..160];
        var s = Core.BelTMath.H[192..208];
        var x = Core.BelTMath.H[..48];

        var expectedY = new byte[] 
        {
            0x10, 0x11, 0x6E, 0xFA, 0xE6, 0xAD, 0x58, 0xEE, 
            0x14, 0x85, 0x2E, 0x11, 0xDA, 0x1B, 0x8A, 0x74, 
            0x5C, 0xF2, 0x48, 0x0E, 0x8D, 0x03, 0xF1, 0xC1, 
            0x94, 0x92, 0xE5, 0x3E, 0xD3, 0xA7, 0x0F, 0x60,
            0x65, 0x7C, 0x1E, 0xE8, 0xC0, 0xE0, 0xAE, 0x5B,
            0x58, 0x38, 0x8B, 0xF8, 0xA6, 0x8E, 0x33, 0x09
        };

        var actualY = new byte[x.Length];
        _cbc.Encrypt(x, k, s, actualY);


        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");
        Assert.That(actualY, Is.EqualTo(expectedY), "CBC Full Blocks Encrypt failed (Table A.11)");
    }

    [Test]
    public void Encrypt_TableA11_PartialBlock()
    {
        // Данные из таблицы А.11 (41 байт)
        var k = Core.BelTMath.H[128..160];
        var s = Core.BelTMath.H[192..208];
        var x = Core.BelTMath.H[..36];

        // ВАЖНО: При краже шифртекста Y должен быть той же длины (41 байт)
        var expectedY = new byte[] 
        {
            0x10, 0x11, 0x6E, 0xFA, 0xE6, 0xAD, 0x58, 0xEE, 
            0x14, 0x85, 0x2E, 0x11, 0xDA, 0x1B, 0x8A, 0x74, 
            0x6A, 0x9B, 0xBA, 0xDC, 0xAF, 0x73, 0xF9, 0x68,
            0xF8, 0x75, 0xDE, 0xDC, 0x0A, 0x44, 0xF6, 0xB1,
            0x5C, 0xF2, 0x48, 0x0E
        };

        var actualY = new byte[x.Length];
        _cbc.Encrypt(x, k, s, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");
        Assert.That(actualY, Is.EqualTo(expectedY), "CBC Partial Block Encrypt failed (Table A.11)");
    }

    [Test]
    public void Decrypt_TableA12_Case2_FullBlocks()
    {
        var k = Core.BelTMath.H[160..192];
        var s = Core.BelTMath.H[208..224];
        var y = Core.BelTMath.H[64..112];

        var expectedX = new byte[] 
        {
            0x73, 0x08, 0x94, 0xD6, 0x15, 0x8E, 0x17, 0xCC, 
            0x16, 0x00, 0x18, 0x5A, 0x8F, 0x41, 0x1C, 0xAB, 
            0x04, 0x71, 0xFF, 0x85, 0xC8, 0x37, 0x92, 0x39, 
            0x8D, 0x89, 0x24, 0xEB, 0xD5, 0x7D, 0x03, 0xDB,
            0x95, 0xB9, 0x7A, 0x9B, 0x79, 0x07, 0xE4, 0xB0,
            0x20, 0x96, 0x04, 0x55, 0xE4, 0x61, 0x76, 0xF8
        };

        var actualX = new byte[y.Length];
        _cbc.Decrypt(y, k, s, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");
        Assert.That(actualX, Is.EqualTo(expectedX), "CBC Full Blocks Decrypt failed (Table A.12, Case 2)");
    }

    [Test]
    public void Decrypt_TableA12_Case2_PartialBlock()
    {
        var k = Core.BelTMath.H[160..192];
        var s = Core.BelTMath.H[208..224];
        var y = Core.BelTMath.H[64..100];

        var expectedX = new byte[] 
        {
            0x73, 0x08, 0x94, 0xD6, 0x15, 0x8E, 0x17, 0xCC, 
            0x16, 0x00, 0x18, 0x5A, 0x8F, 0x41, 0x1C, 0xAB, 
            0xB6, 0xAB, 0x7A, 0xF8, 0x54, 0x1C, 0xF8, 0x57,
            0x55, 0xB8, 0xEA, 0x27, 0x23, 0x9F, 0x08, 0xD2,
            0x16, 0x66, 0x46, 0xE4 
        };


        var actualX = new byte[y.Length];
        _cbc.Decrypt(y, k, s, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");
        Assert.That(actualX, Is.EqualTo(expectedX), "CBC Partial Block Decrypt failed (Table A.12, Case 2)");
    }
}