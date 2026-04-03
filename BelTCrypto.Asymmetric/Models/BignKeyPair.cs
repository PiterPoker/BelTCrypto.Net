using System.Numerics;

namespace BelTCrypto.Bign.Models;

public record BignKeyPair(BigInteger PrivateKey, ECPoint PublicKey);
