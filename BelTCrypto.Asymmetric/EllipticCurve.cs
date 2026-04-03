using BelTCrypto.Bign.Interfaces;
using BelTCrypto.Bign.Models;
using System.Numerics;

namespace BelTCrypto.Bign;

public class EllipticCurve : IEllipticCurve
{
    public BigInteger A { get; }
    public BigInteger B { get; }
    public FiniteField Field { get; }

    public BigInteger P { get; }

    public BigInteger Q { get; }

    public ECPoint G { get; }

    public EllipticCurve(BigInteger a, BigInteger b, BigInteger p, BigInteger q, ECPoint g)
    {
        A = a;
        B = b;
        P = p; 
        Q = q; 
        G = g;
        Field = new FiniteField(p);

        // Проверка дискриминанта: 4a^3 + 27b^2 != 0
        var disc = Field.Add(
            Field.Multiply(4, BigInteger.ModPow(a, 3, Field.P)),
            Field.Multiply(27, BigInteger.ModPow(b, 2, Field.P))
        );
        if (disc == 0) throw new ArgumentException("Кривая вырожденная (сингулярная).");
    }

    public ECPoint Add(ECPoint p1, ECPoint p2)
    {
        // 1. Обработка бесконечно удаленной точки
        if (p1.IsInfinity) return p2;
        if (p2.IsInfinity) return p1;

        // 2. Проверка на противоположные точки: P + (-P) = O
        if (p1.X == p2.X && Field.Subtract(0, p1.Y) == p2.Y % Field.P)
            return ECPoint.Infinity;

        BigInteger lambda;
        if (p1 == p2) // Удвоение точки (P1 = P2)
        {
            // lambda = (3*x1^2 + a) / (2*y1)
            var numerator = Field.Add(Field.Multiply(3, Field.Multiply(p1.X, p1.X)), A);
            var denominator = Field.Add(p1.Y, p1.Y);
            lambda = Field.Divide(numerator, denominator);
        }
        else // Сложение разных точек (P1 != P2)
        {
            // lambda = (y2 - y1) / (x2 - x1)
            var numerator = Field.Subtract(p2.Y, p1.Y);
            var denominator = Field.Subtract(p2.X, p1.X);
            lambda = Field.Divide(numerator, denominator);
        }

        // x3 = lambda^2 - x1 - x2
        var x3 = Field.Subtract(Field.Subtract(Field.Multiply(lambda, lambda), p1.X), p2.X);

        // y3 = lambda*(x1 - x3) - y1
        var y3 = Field.Subtract(Field.Multiply(lambda, Field.Subtract(p1.X, x3)), p1.Y);

        return new ECPoint(x3, y3);
    }
    public ECPoint Multiply(ECPoint p, BigInteger k)
    {
        if (k == 0 || p.IsInfinity) return ECPoint.Infinity;
        if (k < 0) return Multiply(Negate(p), -k);

        ECPoint result = ECPoint.Infinity;
        ECPoint addend = p;

        while (k > 0)
        {
            if ((k & 1) == 1)
                result = Add(result, addend);

            addend = Add(addend, addend);
            k >>= 1;
        }
        return result;
    }

    public ECPoint Negate(ECPoint p) =>
        p.IsInfinity ? p : new ECPoint(p.X, Field.Subtract(0, p.Y));
}
