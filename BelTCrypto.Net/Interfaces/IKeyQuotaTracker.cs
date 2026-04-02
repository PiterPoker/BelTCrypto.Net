namespace BelTCrypto.Net.Interfaces;

public interface IKeyQuotaTracker
{
    /// <summary>
    /// Проверяет остаток квоты ключа и атомарно инкрементирует счетчик.
    /// Выбрасывает CryptographicException, если квота исчерпана.
    /// </summary>
    void EnsureQuotaAndIncrement(Guid keyId, BelTEncryptionMode mode, long requiredAmount);
    long GetRemainingQuota(Guid keyId, BelTEncryptionMode mode);
}