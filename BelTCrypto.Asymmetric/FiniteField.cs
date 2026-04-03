using System.Numerics;

namespace BelTCrypto.Bign;

public class FiniteField
{
    public BigInteger P { get; }

    public FiniteField(BigInteger prime)
    {
        P = prime;
    }

    public BigInteger Add(BigInteger a, BigInteger b)
    {
        return (a + b) % P;
    }

    public BigInteger Subtract(BigInteger a, BigInteger b)
    {
        // Важно: обрабатываем отрицательный результат в C#
        BigInteger res = (a - b) % P;
        return res < 0 ? res + P : res;
    }

    public BigInteger Multiply(BigInteger a, BigInteger b)
    {
        return (a * b) % P;
    }

    /// <summary>
    /// Деление a / b в поле Fp.
    /// Выполняется как a * (b^-1) mod p.
    /// </summary>
    public BigInteger Divide(BigInteger a, BigInteger b)
    {
        return Multiply(a, ModInverse(b));
    }

    /// <summary>
    /// Поиск обратного элемента: b^-1 mod p.
    /// Т.к. P в СТБ - простое число, используем Малую теорему Ферма: b^(p-2) mod p.
    /// </summary>
    public BigInteger ModInverse(BigInteger n)
    {
        if (n == 0) throw new DivideByZeroException("Обратного элемента для 0 не существует.");
        return BigInteger.ModPow(n, P - 2, P);
    }

    /// <summary>
    /// Символ Лежандра (a/p). 
    /// Возвращает 1 (вычет), -1 (невычет) или 0.
    /// </summary>
    public int LegendreSymbol(BigInteger a)
    {
        if (a % P == 0) return 0;
        // Используем критерий Эйлера: a^((p-1)/2) mod p
        var res = BigInteger.ModPow(a, (P - 1) / 2, P);
        return res == 1 ? 1 : -1;
    }
}