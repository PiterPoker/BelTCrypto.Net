using System.Numerics;

namespace BelTCrypto.Bign.Models;

public record ECPoint
{
    public BigInteger X { get; init; }
    public BigInteger Y { get; init; }
    public bool IsInfinity { get; init; }

    private ECPoint() => IsInfinity = true;

    public ECPoint(BigInteger x, BigInteger y)
    {
        X = x;
        Y = y;
        IsInfinity = false;
    }

    public static ECPoint Infinity => new();
}
