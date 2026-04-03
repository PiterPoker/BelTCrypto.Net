using BelTCrypto.Bign.Models;
using System.Numerics;

namespace BelTCrypto.Bign.Interfaces;

public interface IEllipticCurve
{
    BigInteger P { get; } // Модуль поля
    BigInteger A { get; } // Параметр a
    BigInteger B { get; } // Параметр b
    BigInteger Q { get; } // Порядок группы точек
    ECPoint G { get; }    // Базовая точка

    ECPoint Add(ECPoint p1, ECPoint p2);
    ECPoint Multiply(ECPoint p, BigInteger k);
}