using BelTCrypto.Core;

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
        Assert.That(BeltHash.SubstituteH(input), Is.EqualTo(expected));
    }

    [Test]
    public void RotHi_32Bit_ValidShift()
    {
        // Пример из 4.2.2: RotHi для 32-битного слова
        uint value = 0xB194BAC8;
        // В стандарте RotHi определен как циклический сдвиг влево
        uint expected = (value << 1) | (value >> 31);
        Assert.That(BeltHash.RotHi(value, 1), Is.EqualTo(expected));
    }
}
