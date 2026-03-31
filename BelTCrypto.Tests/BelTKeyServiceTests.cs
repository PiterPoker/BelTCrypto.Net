using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTKeyServiceTests
{

    private IBelTKeyService _keyService;

    [SetUp]
    public void Setup()
    {
        _keyService = BelTKeyServiceFactory.Create();
    }

    /// <summary>
    /// Тест согласно Таблице А.27 для n = 4
    /// </summary>
    [Test]
    public void KeyExpand_N4_ReturnsCorrectKey()
    {
        // Данные из таблицы А.27
        // K1..K4: E9DEE72C 8F0C0FA6 2DDB49F4 6F739647
        byte[] sourceKey = [
            0xE9, 0xDE, 0xE7, 0x2C,
            0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4,
            0x6F, 0x73, 0x96, 0x47,
        ];

        // Ожидаемый результат K: повторение K1..K4 дважды
        byte[] expected =
        [
            0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
            0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47
        ];

        byte[] actual = new byte[32];

        // Действие
        _keyService.Expand(sourceKey, actual);

        TestContext.Out.WriteLine($"Actual Key:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected Key: {BitConverter.ToString(expected)}");

        // Проверка
        Assert.That(actual, Is.EqualTo(expected), "Расширение ключа для n=4 (128 бит) выполнено некорректно.");
    }

    /// <summary>
    /// Тест согласно Таблице А.27 для n = 6
    /// </summary>
    [Test]
    public void KeyExpand_N6_ReturnsCorrectKey()
    {
        // Данные из таблицы А.27
        // K1..K6: E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37
        byte[] sourceKey = [
            0xE9, 0xDE, 0xE7, 0x2C,
            0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4,
            0x6F, 0x73, 0x96, 0x47,
            0x06, 0x07, 0x53, 0x16,
            0xED, 0x24, 0x7A, 0x37
        ];

        // Ожидаемый результат K: повторение K1..K4 дважды
        byte[] expected =
        [
            0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
            0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37,
            0x4B, 0x09, 0xA1, 0x7E, 0x84, 0x50, 0xBF, 0x66
        ];

        byte[] actual = new byte[32];

        // Действие
        _keyService.Expand(sourceKey, actual);

        TestContext.Out.WriteLine($"Actual Key:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected Key: {BitConverter.ToString(expected)}");

        // Проверка
        Assert.That(actual, Is.EqualTo(expected), "Расширение ключа для n=6 (192 бит) выполнено некорректно.");
    }

    [Test]
    public void KeyRep_M128_ReturnsCorrectKey()
    {
        // Данные из таблицы А.27
        // K1..K6: E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37
        byte[] sourceKey = [
            0xE9, 0xDE, 0xE7, 0x2C,
            0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4,
            0x6F, 0x73, 0x96, 0x47,
            0x06, 0x07, 0x53, 0x16,
            0xED, 0x24, 0x7A, 0x37,
            0x39, 0xCB, 0xA3, 0x83, 
            0x03, 0xA9, 0x8B, 0xF6
        ];

        byte[] d = [
            0x01, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];

        byte[] i = [
            0x5B, 0xE3, 0xD6, 0x12, 
            0x17, 0xB9, 0x61, 0x81, 
            0xFE, 0x67, 0x86, 0xAD,
            0x71, 0x6B, 0x89, 0x0B
        ];

        int mBits = 128;

        // Ожидаемый результат K: повторение K1..K4 дважды
        byte[] expected =
        [
            0x6B, 0xBB, 0xC2, 0x33, 0x66, 0x70, 0xD3, 0x1A, 
            0xB8, 0x3D, 0xAA, 0x90, 0xD5, 0x2C, 0x05, 0x41
        ];

        byte[] actual = new byte[mBits/8];

        // Действие
        _keyService.Rep(sourceKey, d, i, mBits, actual);

        TestContext.Out.WriteLine($"Actual Key:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected Key: {BitConverter.ToString(expected)}");

        // Проверка
        Assert.That(actual, Is.EqualTo(expected), "Преобразование ключа (Rep) для m=128 выполнено некорректно.");
    }

    [Test]
    public void KeyRep_M192_ReturnsCorrectKey()
    {
        byte[] sourceKey = [
            0xE9, 0xDE, 0xE7, 0x2C,
            0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4,
            0x6F, 0x73, 0x96, 0x47,
            0x06, 0x07, 0x53, 0x16,
            0xED, 0x24, 0x7A, 0x37,
            0x39, 0xCB, 0xA3, 0x83,
            0x03, 0xA9, 0x8B, 0xF6
        ];

        byte[] d = [
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];

        byte[] i = [
            0x5B, 0xE3, 0xD6, 0x12,
            0x17, 0xB9, 0x61, 0x81,
            0xFE, 0x67, 0x86, 0xAD,
            0x71, 0x6B, 0x89, 0x0B
        ];

        int mBits = 192;

        // Ожидаемый результат K: повторение K1..K4 дважды
        byte[] expected =
        [
            0x9A, 0x25, 0x32, 0xA1, 0x8C, 0xBA, 0xF1, 0x45, 
            0x39, 0x8D, 0x5A, 0x95, 0xFE, 0xEA, 0x6C, 0x82, 
            0x5B, 0x9C, 0x19, 0x71, 0x56, 0xA0, 0x02, 0x75
        ];

        byte[] actual = new byte[mBits / 8];

        // Действие
        _keyService.Rep(sourceKey, d, i, mBits, actual);

        TestContext.Out.WriteLine($"Actual Key:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected Key: {BitConverter.ToString(expected)}");

        // Проверка
        Assert.That(actual, Is.EqualTo(expected), "Преобразование ключа (Rep) для m=192 выполнено некорректно.");
    }



    [Test]
    public void KeyRep_M256_ReturnsCorrectKey()
    {
        byte[] sourceKey = [
            0xE9, 0xDE, 0xE7, 0x2C,
            0x8F, 0x0C, 0x0F, 0xA6,
            0x2D, 0xDB, 0x49, 0xF4,
            0x6F, 0x73, 0x96, 0x47,
            0x06, 0x07, 0x53, 0x16,
            0xED, 0x24, 0x7A, 0x37,
            0x39, 0xCB, 0xA3, 0x83,
            0x03, 0xA9, 0x8B, 0xF6
        ];

        byte[] d = [
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        ];

        byte[] i = [
            0x5B, 0xE3, 0xD6, 0x12,
            0x17, 0xB9, 0x61, 0x81,
            0xFE, 0x67, 0x86, 0xAD,
            0x71, 0x6B, 0x89, 0x0B
        ];

        int mBits = 256;

        // Ожидаемый результат K: повторение K1..K4 дважды
        byte[] expected =
        [
            0x76, 0xE1, 0x66, 0xE6, 0xAB, 0x21, 0x25, 0x6B,
            0x67, 0x39, 0x39, 0x7B, 0x67, 0x2B, 0x87, 0x96,
            0x14, 0xB8, 0x1C, 0xF0, 0x59, 0x55, 0xFC, 0x3A,
            0xB0, 0x93, 0x43, 0xA7, 0x45, 0xC4, 0x8F, 0x77
        ];

        byte[] actual = new byte[mBits / 8];

        // Действие
        _keyService.Rep(sourceKey, d, i, mBits, actual);

        TestContext.Out.WriteLine($"Actual Key:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected Key: {BitConverter.ToString(expected)}");

        // Проверка
        Assert.That(actual, Is.EqualTo(expected), "Преобразование ключа (Rep) для m=256 выполнено некорректно.");
    }
}
