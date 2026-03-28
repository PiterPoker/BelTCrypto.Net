using BelTCrypto.Core.Old;
using BelTCrypto.Net;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTMathTests
{
    [Test]
    public void SubstitutionH_ValidInput_ReturnsExpectedValue()
    {
        // Пример из стандарта: H(A2) = 9B
        byte input = 0xA2;
        byte expected = 0x9B;
        Assert.That(BeltHashOld.SubstituteH(input), Is.EqualTo(expected));
    }

    [Test]
    public void RotHi_32Bit_ValidShift()
    {
        // Пример из 4.2.2: RotHi для 32-битного слова
        uint value = 0xB194BAC8;
        // В стандарте RotHi определен как циклический сдвиг влево
        uint expected = (value << 1) | (value >> 31);
        Assert.That(BeltHashOld.RotHi(value, 1), Is.EqualTo(expected));
    }

    [Test]
    [Description("Проверка операции умножения в поле GF(2^128) из таблицы А.18")]
    public void MultiplyGF128_TableA18_Test()
    {
        // Пример 1 из таблицы А.18
        // u: 34904055 11BE3297 1343724C 5AB793E9 -> переворачиваем байты для Little-Endian
        byte[] u = [.. Convert.FromHexString("3490405511BE32971343724C5AB793E9")];
        // v: 22481783 8761A9D6 E3EC9689 110FB0F3
        byte[] v = [.. Convert.FromHexString("224817838761A9D6E3EC9689110FB0F3")];
        // Ожидаемый u*v: 0001D107 FC67DE40 04DC2C80 3DFD95C3
        byte[] expected = [.. Convert.FromHexString("0001D107FC67DE4004DC2C803DFD95C3")];

        BeltHashOld.MultiplyGF128(u, v);

        Assert.That(u, Is.EqualTo(expected), "Ошибка в первом примере умножения А.18");

        // Пример 2 из таблицы А.18
        byte[] u2 = [.. Convert.FromHexString("703FCCF095EE8DF1C1ABF8EE8DF1C1AB")];
        byte[] v2 = [.. Convert.FromHexString("2055704E2EDB48FE87E74075A5E77EB1")];
        byte[] expected2 = [.. Convert.FromHexString("4A5C95938B3FE8F674D59BC1EB356079")];

        BeltHashOld.MultiplyGF128(u2, v2);

        Assert.That(u2, Is.EqualTo(expected2), "Ошибка во втором примере умножения А.18");
    }
}
