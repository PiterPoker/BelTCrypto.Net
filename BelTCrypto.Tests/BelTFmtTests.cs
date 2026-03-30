using BelTCrypto.Core;
using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTFmtTests
{
    private IBelTFmt _fmt;

    [SetUp]
    public void Setup()
    {
        _fmt = BeltFmtFactory.Create();
    }

    [Test]
    public void Encipher_TableA26_ShouldGenerateCorrectY10x10()
    {
        // --- 1. Исходные данные из таблицы А.26 ---
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];

        TestContext.Out.WriteLine($"k:   {BitConverter.ToString(k)}");
        TestContext.Out.WriteLine($"s: {BitConverter.ToString(s)}");
        int m = 10;
        ushort[] x = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

        // --- 2. Ожидаемый результат Y ---
        ushort[] expectedY = { 6, 9, 3, 4, 7, 7, 0, 3, 5, 2 };

        // Буфер для результата
        ushort[] actualY = new ushort[x.Length];

        // --- 3. Выполнение зашифрования ---
        _fmt.Encrypt(x, m, k, s, actualY);

        // Логирование для отладки
        TestContext.Out.WriteLine($"Input X:    {string.Join(",", x)}");
        TestContext.Out.WriteLine($"Actual Y:   {string.Join(",", actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {string.Join(",", expectedY)}");

        // --- 4. Проверка ---
        Assert.That(actualY, Is.EqualTo(expectedY), "Зашифрованное слово Y не совпадает с эталоном А.26");
    }

    [Test]
    public void Encipher_TableA26_ShouldGenerateCorrectY58x21()
    {
        // --- 1. Исходные данные из таблицы А.26 ---
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];

        TestContext.Out.WriteLine($"k:   {BitConverter.ToString(k)}");
        TestContext.Out.WriteLine($"s: {BitConverter.ToString(s)}");
        int m = 58;
        ushort[] x = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

        // --- 2. Ожидаемый результат Y ---
        ushort[] expectedY = { 7, 4, 6, 21, 49, 55, 24, 23, 22, 50, 27, 39, 24, 24, 17, 32, 57, 43, 26, 5, 29 };

        // Буфер для результата
        ushort[] actualY = new ushort[x.Length];

        // --- 3. Выполнение зашифрования ---
        _fmt.Encrypt(x, m, k, s, actualY);

        // Логирование для отладки
        TestContext.Out.WriteLine($"Input X:    {string.Join(",", x)}");
        TestContext.Out.WriteLine($"Actual Y:   {string.Join(",", actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {string.Join(",", expectedY)}");

        // --- 4. Проверка ---
        Assert.That(actualY, Is.EqualTo(expectedY), "Зашифрованное слово Y не совпадает с эталоном А.26");
    }

    [Test]
    public void Encipher_TableA26_ShouldGenerateCorrectY65536x17()
    {
        // --- 1. Исходные данные из таблицы А.26 ---
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];

        TestContext.Out.WriteLine($"k:   {BitConverter.ToString(k)}");
        TestContext.Out.WriteLine($"s: {BitConverter.ToString(s)}");
        int m = 65536;
        ushort[] x = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        // --- 2. Ожидаемый результат Y ---
        ushort[] expectedY = { 14290,31359,58054,51842,44653,34762,28652,48929,6541,13788,7784,46182,61098,43056,3564,21568,63878 };

        // Буфер для результата
        ushort[] actualY = new ushort[x.Length];

        // --- 3. Выполнение зашифрования ---
        _fmt.Encrypt(x, m, k, s, actualY);

        // Логирование для отладки
        TestContext.Out.WriteLine($"Input X:    {string.Join(",", x)}");
        TestContext.Out.WriteLine($"Actual Y:   {string.Join(",", actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {string.Join(",", expectedY)}");

        // --- 4. Проверка ---
        Assert.That(actualY, Is.EqualTo(expectedY), "Зашифрованное слово Y не совпадает с эталоном А.26");
    }

    [Test]
    public void Decipher_TableA26_ShouldGenerateCorrectX10x10()
    {
        // --- 1. Исходные данные из таблицы А.26 ---
        // Те же ключи и параметры, что и в тесте на зашифрование
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];
        int m = 10;

        // Входное слово для расшифрования — это результат (Y) из таблицы А.26
        ushort[] y = { 6, 9, 3, 4, 7, 7, 0, 3, 5, 2 };

        // Ожидаемый результат — исходное слово X
        ushort[] expectedX = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

        // Буфер для результата расшифрования
        ushort[] actualX = new ushort[y.Length];

        // --- 2. Выполнение расшифрования ---
        _fmt.Decrypt(y, m, k, s, actualX);

        // Логирование
        TestContext.Out.WriteLine($"Input Y:    {string.Join(",", y)}");
        TestContext.Out.WriteLine($"Actual X:   {string.Join(",", actualX)}");
        TestContext.Out.WriteLine($"Expected X: {string.Join(",", expectedX)}");

        // --- 3. Проверка ---
        Assert.That(actualX, Is.EqualTo(expectedX), "Расшифрованное слово X не совпадает с эталоном А.26");
    }
    [Test]
    public void Decipher_TableA26_ShouldGenerateCorrectX58x21()
    {
        // --- 1. Исходные данные из таблицы А.26 ---
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];
        int m = 58;

        // Входное слово Y из таблицы А.26
        ushort[] y = { 7, 4, 6, 21, 49, 55, 24, 23, 22, 50, 27, 39, 24, 24, 17, 32, 57, 43, 26, 5, 29 };

        // Ожидаемый результат X
        ushort[] expectedX = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

        // Буфер для результата
        ushort[] actualX = new ushort[y.Length];

        // --- 2. Выполнение расшифрования ---
        _fmt.Decrypt(y, m, k, s, actualX);

        // Логирование
        TestContext.Out.WriteLine($"Input Y:    {string.Join(",", y)}");
        TestContext.Out.WriteLine($"Actual X:   {string.Join(",", actualX)}");
        TestContext.Out.WriteLine($"Expected X: {string.Join(",", expectedX)}");

        // --- 3. Проверка ---
        Assert.That(actualX, Is.EqualTo(expectedX), "Расшифрованное слово X (58x21) не совпадает с эталоном А.26");
    }

    [Test]
    public void Decipher_TableA26_ShouldGenerateCorrectX65536x17()
    {
        // --- 1. Исходные данные из таблицы А.26 ---
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];
        int m = 65536;

        // Входное слово Y из таблицы А.26
        ushort[] y = { 14290, 31359, 58054, 51842, 44653, 34762, 28652, 48929, 6541, 13788, 7784, 46182, 61098, 43056, 3564, 21568, 63878 };

        // Ожидаемый результат X
        ushort[] expectedX = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        // Буфер для результата
        ushort[] actualX = new ushort[y.Length];

        // --- 2. Выполнение расшифрования ---
        _fmt.Decrypt(y, m, k, s, actualX);

        // Логирование
        TestContext.Out.WriteLine($"Input Y:    {string.Join(",", y)}");
        TestContext.Out.WriteLine($"Actual X:   {string.Join(",", actualX)}");
        TestContext.Out.WriteLine($"Expected X: {string.Join(",", expectedX)}");

        // --- 3. Проверка ---
        Assert.That(actualX, Is.EqualTo(expectedX), "Расшифрованное слово X (65536x17) не совпадает с эталоном А.26");
    }
}