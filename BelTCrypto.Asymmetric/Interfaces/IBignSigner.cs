using BelTCrypto.Bign.Models;
using System.Numerics;

namespace BelTCrypto.Bign.Interfaces;

public interface IBignSigner
{
    // Выработка подписи (Section 7.1)
    // Возвращает (r, s) упакованные в байты
    byte[] Sign(byte[] message, BigInteger privateKey);

    // Проверка подписи (Section 7.1)
    bool Verify(byte[] message, byte[] signature, ECPoint publicKey);
}
