using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTDwpTests
{
    private IAuthenticatedEncryption _dwp;

    [SetUp]
    public void Setup() => _dwp = BelTAuthenticatedFactory.Create(BelTAuthenticatedFactory.BeltAeadScheme.Dwp);

    [Test]
    public void Protect_TableA19_Success()
    {
        // Данные из таблицы А.19
        byte[] i = Core.BelTMath.H[16..48];

        byte[] k = Core.BelTMath.H[128..160];

        byte[] s = Core.BelTMath.H[192..208];

        byte[] x = Core.BelTMath.H[..16];

        byte[] expectedY = [
            0x52, 0xC9, 0xAF, 0x96, 0xFF, 0x50, 0xF6, 0x44,
            0x35, 0xFC, 0x43, 0xDE, 0xF5, 0x6B, 0xD7, 0x97
        ];

        byte[] expectedT = [
            0x3B, 0x2E, 0x0A, 0xEB, 0x2B, 0x91, 0x85, 0x4B
        ];

        // Выделяем буферы под результат
        Span<byte> actualY = new byte[x.Length];
        Span<byte> actualT = new byte[8];

        _dwp.Protect(x, i, k, s, actualY, actualT);

        // Логируем для отладки
        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY.ToArray())}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");
        TestContext.Out.WriteLine($"Actual T:   {BitConverter.ToString(actualT.ToArray())}");
        TestContext.Out.WriteLine($"Expected T: {BitConverter.ToString(expectedT)}");

        using (Assert.EnterMultipleScope())
        {
            // Проверки
            Assert.That(actualY.ToArray(), Is.EqualTo(expectedY).AsCollection, "Шифртекст Y не совпал.");
            Assert.That(actualT.ToArray(), Is.EqualTo(expectedT).AsCollection, "Имитовставка T не совпала.");
        }
    }

    [Test]
    public void Unprotect_TableA20_ShouldRestoreOriginalX()
    {
        // 1. Исходные данные из таблицы А.20
        byte[] i = Core.BelTMath.H[80..112];
        byte[] k = Core.BelTMath.H[160..192];
        byte[] s = Core.BelTMath.H[208..224];
        byte[] y = Core.BelTMath.H[64..80];
        byte[] t = [
            0x6A, 0x2C, 0x2C, 0x94, 0xC4, 0x15, 0x0D, 0xC0
        ];

        // Ожидаемый результат
        byte[] expectedX = [
            0xDF, 0x18, 0x1E, 0xD0, 0x08, 0xA2, 0x0F, 0x43,
            0xDC, 0xBB, 0xB9, 0x36, 0x50, 0xDA, 0xD3, 0x4B
        ];

        // 2. Буфер для результата
        Span<byte> actualX = stackalloc byte[y.Length];

        // 3. Выполнение снятия защиты
        bool isValid = _dwp.Unprotect(y, i, t, k, s, actualX);

        // Логируем для отладки
        TestContext.Out.WriteLine($"Actual X:   {BitConverter.ToString(actualX.ToArray())}");
        TestContext.Out.WriteLine($"Expected X: {BitConverter.ToString(expectedX)}");
        // 4. Проверки
        using (Assert.EnterMultipleScope())
        {
            Assert.That(isValid, Is.True, "Имитовставка T должна быть признана верной.");
            Assert.That(actualX.ToArray(), Is.EqualTo(expectedX),
                "Расшифрованные данные X не совпадают с эталоном из таблицы А.20.");
        }
    }
}
