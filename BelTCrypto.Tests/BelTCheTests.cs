using BelTCrypto.Core;
using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTCheTests
{
    private IAuthenticatedEncryption _che;

    [SetUp]
    public void Setup() => _che = BelTAuthenticatedFactory.Create(BelTAuthenticatedFactory.BeltAeadScheme.Che);
    [Test]
    public void Protect_TableA19_ShouldGenerateCorrectYAndT()
    {
        // 1. Исходные данные из таблицы А.19
        // Данные из таблицы А.19
        byte[] i = Core.BelTMath.H[16..48];
        byte[] k = Core.BelTMath.H[128..160];
        byte[] s = Core.BelTMath.H[192..208];
        byte[] X = Core.BelTMath.H[..15];

        // --- 2. Ожидаемые результаты ---
        byte[] expectedY = [
            0xBF, 0x3D, 0xAE, 0xAF, 0x5D, 0x18, 0xD2, 0xBC, 0xC3, 0x0E, 0xA6, 0x2D, 0x2E, 0x70, 0xA4
            ];
        byte[] expectedT = [
            0x54, 0x86, 0x22, 0xB8, 0x44, 0x12, 0x3F, 0xF7
            ];

        // 2. Буферы для результата
        Span<byte> actualY = stackalloc byte[X.Length];
        Span<byte> actualT = stackalloc byte[8];

        // 3. Выполнение установки защиты
        _che.Protect(X, i, k, s, actualY, actualT);

        // Логирование для отладки
        TestContext.Out.WriteLine($"Actual Y:   {Convert.ToHexString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {Convert.ToHexString(expectedY)}");
        TestContext.Out.WriteLine($"Actual T:   {Convert.ToHexString(actualT)}");
        TestContext.Out.WriteLine($"Expected T: {Convert.ToHexString(expectedT)}");

        // 4. Проверки
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Convert.ToHexString(actualY), Is.EqualTo(Convert.ToHexString(expectedY)),
                "Шифртекст Y не совпадает с эталоном А.19");
            Assert.That(Convert.ToHexString(actualT), Is.EqualTo(Convert.ToHexString(expectedT)),
                "Имитовставка T не совпадает с эталоном А.19");
        }
    }

    [Test]
    public void Unprotect_TableA20_ShouldRestoreXAndVerifyT()
    {
        // --- Входные данные Таблицы А.20 ---

        byte[] i = Core.BelTMath.H[80..112];
        byte[] k = Core.BelTMath.H[160..192];
        byte[] s = Core.BelTMath.H[208..224];
        byte[] y = Core.BelTMath.H[64..84];
        byte[] t = [
            0x7D, 0x9D, 0x4F, 0x59, 0xD4, 0x0D, 0x19, 0x7D
        ];

        // Ожидаемый результат
        byte[] expectedX = [
            0x2B, 0xAB, 0xF4, 0x3E, 0xB3, 0x7B, 0x53, 0x98, 
            0xA9, 0x06, 0x8F, 0x31, 0xA3, 0xC7, 0x58, 0xB7, 
            0x62, 0xF4, 0x4A, 0xA9
        ];

        // Твой блок и реализация Che
        var block = new BelTBlock();
        var che = new BelTChe(block);

        byte[] actualX = new byte[y.Length];

        // --- Действие ---
        bool isValid = che.Unprotect(y, i, k, s, t, actualX);

        // --- Проверки NUnit ---
        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True, "Имитовставка T не совпадает с эталоном А.20");

            string actualXHex = Convert.ToHexString(actualX);
            string expectedXHex = Convert.ToHexString(expectedX);

            Assert.That(actualXHex, Is.EqualTo(expectedXHex), "Расшифрованные данные X не совпадают");
        });

        // Лог для контроля в Test Explorer
        TestContext.Out.WriteLine($"Actual X:   {Convert.ToHexString(actualX)}");
        TestContext.Out.WriteLine($"Expected X: {Convert.ToHexString(expectedX)}");
    }
}
