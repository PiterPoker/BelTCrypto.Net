using BelTCrypto.Bign.Models;
using System.Numerics;

namespace BelTCrypto.Bign.Interfaces;

public interface IBignKeyTransport
{
    // Создание токена (отправитель)
    // keyToTransport - секрет, который передаем
    byte[] CreateToken(byte[] keyToTransport, ECPoint recipientPublicKey);

    // Разбор токена (получатель)
    byte[] ParseToken(byte[] token, BigInteger recipientPrivateKey);
}
