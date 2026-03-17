using BelTCrypto.Core;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTCtrTests
{
    private IBelTCtr _ctr;
    private IBelTBlock _block;

    [SetUp]
    public void Setup()
    {
        _block = new BelTBlock(); // Твоя реализация 6.1
        _ctr = new BelTCtr(_block);
    }

    [Test]
    public void Process_TableA15_Encryption_Success()
    {
        // Данные из таблицы А.15
        var k = Core.BelTMath.H[128..160];
        var s = Core.BelTMath.H[192..208];
        var x = Core.BelTMath.H[..48];

        var expectedY = new byte[]
        {
            0x52, 0xC9, 0xAF, 0x96, 0xFF, 0x50, 0xF6, 0x44, 
            0x35, 0xFC, 0x43, 0xDE, 0xF5, 0x6B, 0xD7, 0x97, 
            0xD5, 0xB5, 0xB1, 0xFF, 0x79, 0xFB, 0x41, 0x25, 
            0x7A, 0xB9, 0xCD, 0xF6, 0xE6, 0x3E, 0x81, 0xF8,
            0xF0, 0x03, 0x41, 0x47, 0x3E, 0xAE, 0x40, 0x98, 
            0x33, 0x62, 0x2D, 0xE0, 0x52, 0x13, 0x77, 0x3A
        };

        var actualY = new byte[x.Length];
        _ctr.Process(x, k, s, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");
        Assert.That(actualY, Is.EqualTo(expectedY), "CTR Encryption failed (Table A.15)");
    }

    [Test]
    public void Process_TableA15_Decryption_Is_Inverse()
    {
        // Проверка того, что повторный запуск Process возвращает исходный текст
        var k = Core.BelTMath.H[160..192];
        var s = Core.BelTMath.H[208..224];
        var y = Core.BelTMath.H[64..108];

        var expectedX = new byte[]
        {
            0xDF, 0x18, 0x1E, 0xD0, 0x08, 0xA2, 0x0F, 0x43, 
            0xDC, 0xBB, 0xB9, 0x36, 0x50, 0xDA, 0xD3, 0x4B, 
            0x38, 0x9C, 0xDE, 0xE5, 0x82, 0x6D, 0x40, 0xE2, 
            0xD4, 0xBD, 0x80, 0xF4, 0x9A, 0x93, 0xF5, 0xD2,
            0x12, 0xF6, 0x33, 0x31, 0x66, 0x45, 0x6F, 0x16,
            0x90, 0x43, 0xCC, 0x5F
        };

        var actualX = new byte[y.Length];
        _ctr.Process(y, k, s, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");
        Assert.That(actualX, Is.EqualTo(expectedX), "CTR Decryption failed (Inverse property)");
    }
}
