using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTWideBlockTests
{
    private IBelTWideBlock _wideBlock;

    [SetUp]
    public void Setup()
    {
        _wideBlock = BelTBlockFactory.CreateWide();
    }

    [Test]
    [Description("Таблица А.6, пример 1 (48 байт)")]
    public void Encrypt_48Bytes_ReturnsExpectedValue()
    {
        // Arrange
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..48];
        var expected = new byte[] {
            0x49, 0xA3, 0x8E, 0xE1, 0x08, 0xD6, 0xC7, 0x42,
            0xE5, 0x2B, 0x77, 0x4F, 0x00, 0xA6, 0xEF, 0x98,
            0xB1, 0x06, 0xCB, 0xD1, 0x3E, 0xA4, 0xFB, 0x06,
            0x80, 0x32, 0x30, 0x51, 0xBC, 0x04, 0xDF, 0x76,
            0xE4, 0x87, 0xB0, 0x55, 0xC6, 0x9B, 0xCF, 0x54,
            0x11, 0x76, 0x16, 0x9F, 0x1D, 0xC9, 0xF6, 0xC8
        };
        var actual = new byte[x.Length];

        // Act
        _wideBlock.Encrypt(x, k, actual);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expected)}");

        // Assert
        Assert.That(actual, Is.EqualTo(expected), "Зашифрованное значение Y не совпадает с вектором А.6 (1)");
    }

    [Test]
    [Description("Таблица А.6, пример 2 (44 байта)")]
    public void Encrypt_44Bytes_ReturnsExpectedValue()
    {
        // Arrange
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..47];
        var expected = new byte[]
            {
            0xF0, 0x8E, 0xF2, 0x2D, 0xCA, 0xA0, 0x6C, 0x81,
            0xFB, 0x12, 0x72, 0x19, 0x74, 0x22, 0x1C, 0xA7,
            0xAB, 0x82, 0xC6, 0x28, 0x56, 0xFC, 0xF2, 0xF9,
            0xFC, 0xA0, 0x06, 0xE0, 0x19, 0xA2, 0x8F, 0x16,
            0xE5, 0x82, 0x1A, 0x51, 0xF5, 0x73, 0x59, 0x46,
            0x25, 0xDB, 0xAB, 0x8F, 0x6A, 0x5C, 0x94
            };
        var actual = new byte[x.Length];

        // Act
        _wideBlock.Encrypt(x, k, actual);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expected)}");
        // Assert
        Assert.That(actual, Is.EqualTo(expected), "Зашифрованное значение Y не совпадает с вектором А.6 (2)");
    }

    [Test]
    [Description("Таблица А.7, пример 1 (48 байт)")]
    public void Decrypt_48Bytes_ReturnsExpectedValue()
    {
        // Arrange
        var k = Core.BelTMath.H[160..192];
        var y = Core.BelTMath.H[64..112];
        var expectedX = new byte[] {
            0x92, 0x63, 0x2E, 0xE0, 0xC2, 0x1A, 0xD9, 0xE0, 
            0x9A, 0x39, 0x34, 0x3E, 0x5C, 0x07, 0xDA, 0xA4, 
            0x88, 0x9B, 0x03, 0xF2, 0xE6, 0x84, 0x7E, 0xB1, 
            0x52, 0xEC, 0x99, 0xF7, 0xA4, 0xD9, 0xF1, 0x54, 
            0xB5, 0xEF, 0x68, 0xD8, 0xE4, 0xA3, 0x9E, 0x56, 
            0x71, 0x53, 0xDE, 0x13, 0xD7, 0x22, 0x54, 0xEE
        };
        var actualX = new byte[y.Length];

        // Act
        _wideBlock.Decrypt(y, k, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        // Assert
        Assert.That(actualX, Is.EqualTo(expectedX), "Расшифрованное значение X не совпадает с вектором А.7 (1)");
    }

    [Test]
    [Description("Таблица А.7, пример 2 (33 байта)")]
    public void Decrypt_33Bytes_ReturnsExpectedValue()
    {
        // Arrange
        var k = Core.BelTMath.H[160..192];
        var y = Core.BelTMath.H[64..100];
        var expectedX = new byte[] {
            0xDF, 0x3F, 0x88, 0x22, 0x30, 0xBA, 0xAF, 0xFC, 
            0x92, 0xF0, 0x56, 0x60, 0x32, 0x11, 0x72, 0x31, 
            0x0E, 0x3C, 0xB2, 0x18, 0x26, 0x81, 0xEF, 0x43, 
            0x10, 0x2E, 0x67, 0x17, 0x5E, 0x17, 0x7B, 0xD7, 
            0x5E, 0x93, 0xE4, 0xE8
        };
        var actualX = new byte[y.Length];

        // Act
        _wideBlock.Decrypt(y, k, actualX);

        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");

        // Assert
        Assert.That(actualX, Is.EqualTo(expectedX), "Расшифрованное значение X не совпадает с вектором А.7 (2)");
    }
}