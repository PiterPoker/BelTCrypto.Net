using System.Numerics;

namespace BelTCrypto.Bign.Models;

public record BignCurveParameters(
    string Name,
    BigInteger P,
    BigInteger A,
    BigInteger B,
    BigInteger Q,
    ECPoint G,
    int L
);
