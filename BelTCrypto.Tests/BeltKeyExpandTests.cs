using BelTCrypto.Core;
using System.Buffers.Binary;

namespace BelTCrypto.Tests;

[TestFixture]
public class BeltKeyExpandTests
{
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
        BelTMath.Block.Expand(sourceKey, actual);

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
        BelTMath.Block.Expand(sourceKey, actual);

        TestContext.Out.WriteLine($"Actual Key:   {BitConverter.ToString(actual)}");
        TestContext.Out.WriteLine($"Expected Key: {BitConverter.ToString(expected)}");

        // Проверка
        Assert.That(actual, Is.EqualTo(expected), "Расширение ключа для n=6 (192 бит) выполнено некорректно.");
    }
}
