using BelTCrypto.Core;
using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;
using System.Buffers.Binary;

namespace BelTCrypto.Tests;


[TestFixture]
public class BlockTests
{
    private static readonly (uint a, uint b, uint c, uint d, uint? e)[] ExpectedEncryptTics =
    [
        (0xFB56C62C, 0xCA8EEEB7, 0x09BAD702, 0xCC4E441D, 0x20072EC1),
        (0x7280A094, 0x47BB9CD6, 0x5BD130B1, 0xADA525A4, null),
        (0x00AB0E4D, 0x4B4A6113, 0x73D9CD18, 0x57E54345, null),
        (0xA50D12EF, 0x8CD05085, 0x99A672B7, 0xD9A0C0E4, null),
        (0x21C32063, 0x44712C59, 0xEC21160A, 0xDE08AAB9, null),
        (0xB5279D32, 0xD4579966, 0x251E3B2D, 0xF8EF6A0F, null),
        (0x26349022, 0x08C5172E, 0x705A63C6, 0x5CA6AD61, null),
        (0xD66BC3E0, 0x69CCA1C9, 0xFA88FA6E, 0x3557C9E3, null)
    ];

    private static readonly (uint a, uint b, uint c, uint d)[] ExpectedDencryptTics = [
        (0xA174D6FC, 0x377EB086, 0xBA7C2D07, 0x0DAA044B),
        (0xB01E75B3, 0x0F53A46F, 0x8893A01F, 0xA4E35989),
        (0xB5B85383, 0x33D8BC0E, 0x9A46CD5F, 0xF8D778D4),
        (0x07234634, 0x723B48FC, 0x04690666, 0xADB565F3),
        (0x3141A829, 0x2AD3FB40, 0xD30032B1, 0x4D336185),
        (0xADA2EC35, 0xDADBC720, 0x3421AC22, 0x22EC7943),
        (0x9DAC9289, 0x89A2E5ED, 0x9253A0F0, 0x3B871FA3),
        (0x00CAB840, 0xE993F421, 0x0DC53006, 0xB38448E5)
        ];
    private IBelTBlock _belt;

    [SetUp]
    public void Setup()
    {
        _belt = BelTBlockFactory.Create();
    }

    [Test]
    public void Encrypt_StandardVector_A1_FullTrace()
    {
        // Данные из примера А.1 СТБ 34.101.31
        byte[] key = Core.BelTMath.H[128..(128 + 32)];

        byte[] x = Core.BelTMath.H[..16];

        byte[] expectedY = [
            0x69, 0xCC, 0xA1, 0xC9, 0x35, 0x57, 0xC9, 0xE3,
            0xD6, 0x6B, 0xC3, 0xE0, 0xFA, 0x88, 0xFA, 0x6E
            ];
        byte[] output = new byte[16];

        // Выводим входные данные для контроля
        TestContext.Out.WriteLine($"Input X: {BitConverter.ToString(x)}");

        // Выполняем шифрование
        _belt.Encrypt(x, key, output);

        // Выводим результат
        TestContext.Out.WriteLine($"Encrypt Y: {BitConverter.ToString(output)}");
        TestContext.Out.WriteLine($"Expected X:  {BitConverter.ToString(expectedY)}");

        Assert.That(output.ToArray(), Is.EqualTo(expectedY),
            "Результат шифрования блока не совпадает с Таблицей А.1 (полное шифрование блока).");
    }

    [Test]
    public void Encrypt_VerifyAllTactics_Parametrized()
    {

        // Данные из примера А.1 СТБ 34.101.31
        byte[] key = Core.BelTMath.H[128..(128 + 32)];

        byte[] x = Core.BelTMath.H[..16];

        // 1. Подготовка (X и Key из твоих SBoxH срезов)
        var (a, b, c, d) = BlockUtils.ReadUInt32LittleEndian(x);

        uint[] masterKeys = new uint[8];
        for (int j = 0; j < 8; j++)
            masterKeys[j] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan()[(j * 4)..(j * 4 + 4)]);

        TestContext.Out.WriteLine("=== СТАРТ ШИФРОВАНИЯ ===");

        for (int i = 1; i <= 8; i++)
        {
            // Выполняем такт
            (a, b, c, d) = Core.BelTBlock.ExecuteEncryptStep(a, b, c, d, masterKeys, (uint)i);

            // Ожидаемые значения из твоего массива (уже развернутые для памяти)
            var exp = ExpectedEncryptTics[i - 1];
            uint resA = a.ToRevert();
            uint resB = b.ToRevert();
            uint resC = c.ToRevert();
            uint resD = d.ToRevert();

            // ВЫВОД РЕЗУЛЬТАТОВ ТАКТА
            TestContext.Out.WriteLine($"--- ТАКТ {i} ---");
            TestContext.Out.WriteLine($"A: {resA:X8} | Ожидалось: {exp.a:X8} {(a != exp.a ? "OK" : "ОШИБКА")}");
            TestContext.Out.WriteLine($"B: {resB:X8} | Ожидалось: {exp.b:X8} {(b != exp.b ? "OK" : "ОШИБКА")}");
            TestContext.Out.WriteLine($"C: {resC:X8} | Ожидалось: {exp.c:X8} {(c != exp.c ? "OK" : "ОШИБКА")}");
            TestContext.Out.WriteLine($"D: {resD:X8} | Ожидалось: {exp.d:X8} {(d != exp.d ? "OK" : "ОШИБКА")}");

            // Сверяем (используя твой ToRevert для приведения HEX из стандарта к памяти)
            Assert.Multiple(() =>
            {
                Assert.That(resA, Is.EqualTo(exp.a), $"Tact {i}: A mismatch");
                Assert.That(resB, Is.EqualTo(exp.b), $"Tact {i}: B mismatch");
                Assert.That(resC, Is.EqualTo(exp.c), $"Tact {i}: C mismatch");
                Assert.That(resD, Is.EqualTo(exp.d), $"Tact {i}: D mismatch");
            });
        }
    }

    [Test]
    public void Decrypt_VerifyAllTactics_Parametrized()
    {
        // 1. Подготовка данных
        byte[] key = Core.BelTMath.H[160..(160 + 32)];
        // Вход для расшифрования — это результат шифрования (Таблица А.1)
        byte[] y = Core.BelTMath.H[64..(64 + 16)];

        // Ожидаемый открытый текст X (первые 16 байт H)

        byte[] expectedX = [
            0x0D, 0xC5, 0x30, 0x06, 0x00, 0xCA, 0xB8, 0x40,
            0xB3, 0x84, 0x48, 0xE5, 0xE9, 0x93, 0xF4, 0x21
            ];

        byte[] outputX = new byte[16];

        // Согласно пункту 6.1.2: входной блок Y разбивается на b, d, a, c
        // Мы можем прочитать их напрямую через ReadUInt32LittleEndian
        var (a, b, c, d) = BlockUtils.ReadUInt32LittleEndian(y);

        uint[] masterKeys = new uint[8];
        for (int j = 0; j < 8; j++)
            masterKeys[j] = BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan()[(j * 4)..(j * 4 + 4)]);

        TestContext.Out.WriteLine("=== СТАРТ РАСШИФРОВАНИЯ ===");

        for (int i = 8; i >= 1; i--)
        {
            // 1. Выполняем такт расшифрования
            (a, b, c, d) = Core.BelTBlock.ExecuteDecryptStep(a, b, c, d, masterKeys, (uint)i);

            // 2. Индекс в массиве: Такт 8 -> Индекс 0, Такт 7 -> Индекс 1...
            var exp = ExpectedDencryptTics[8 - i];

            // 3. Вывод для отладки (используем ToRevert, так как в таблице BE)
            uint resA = a.ToRevert();
            uint resB = b.ToRevert();
            uint resC = c.ToRevert();
            uint resD = d.ToRevert();

            TestContext.Out.WriteLine($"--- ТАКТ {i} ---");
            // Теперь имена переменных в коде и в таблице СИНХРОНИЗИРОВАНЫ
            TestContext.Out.WriteLine($"A: {resA:X8} | Ожидалось: {exp.a:X8} {(resA == exp.a ? "OK" : "ERR")}");
            TestContext.Out.WriteLine($"B: {resB:X8} | Ожидалось: {exp.b:X8} {(resB == exp.b ? "OK" : "ERR")}");
            TestContext.Out.WriteLine($"C: {resC:X8} | Ожидалось: {exp.c:X8} {(resC == exp.c ? "OK" : "ERR")}");
            TestContext.Out.WriteLine($"D: {resD:X8} | Ожидалось: {exp.d:X8} {(resD == exp.d ? "OK" : "ERR")}");

            Assert.Multiple(() =>
            {
                Assert.That(resA, Is.EqualTo(exp.a), $"Tact {i}: A mismatch");
                Assert.That(resB, Is.EqualTo(exp.b), $"Tact {i}: B mismatch");
                Assert.That(resC, Is.EqualTo(exp.c), $"Tact {i}: C mismatch");
                Assert.That(resD, Is.EqualTo(exp.d), $"Tact {i}: D mismatch");
            });
        }

        BlockUtils.WriteUInt32LittleEndian(c, a, d, b, outputX);

        Assert.That(outputX, Is.EqualTo(expectedX), "Финальный блок X не совпал с исходным!");
    }

    [Test]
    public void Decrypt_StandardVector_A1_FullTrace()
    {
        // 1. Подготовка данных
        byte[] key = Core.BelTMath.H[160..(160 + 32)];
        // Вход для расшифрования — это результат шифрования (Таблица А.1)
        byte[] y = Core.BelTMath.H[64..(64 + 16)];

        // Ожидаемый открытый текст X (первые 16 байт H)

        byte[] expectedX = [
            0x0D, 0xC5, 0x30, 0x06, 0x00, 0xCA, 0xB8, 0x40,
            0xB3, 0x84, 0x48, 0xE5, 0xE9, 0x93, 0xF4, 0x21
            ];

        byte[] outputX = new byte[16];

        // 2. Выполнение расшифрования
        TestContext.Out.WriteLine($"Input Y: {BitConverter.ToString(y)}");

        _belt.Decrypt(y, key, outputX);

        TestContext.Out.WriteLine($"Decrypted X: {BitConverter.ToString(outputX)}");
        TestContext.Out.WriteLine($"Expected X:  {BitConverter.ToString(expectedX)}");

        // 3. Проверка результата
        Assert.That(outputX, Is.EqualTo(expectedX),
            "Результат расшифрования всего блока не совпал с Таблицей А.1");
    }
}