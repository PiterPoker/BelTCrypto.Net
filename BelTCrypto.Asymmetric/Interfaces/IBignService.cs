namespace BelTCrypto.Bign.Interfaces;

public interface IBignService
{
    // 7.1 Выработка подписи (bign-sign)
    byte[] Sign(byte[] message, byte[] privateKey);

    // 7.1 Проверка подписи (bign-verify)
    bool Verify(byte[] message, byte[] signature, byte[] publicKey);
}
