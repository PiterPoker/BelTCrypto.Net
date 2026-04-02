using BelTCrypto.Net.Interfaces;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

internal class InMemoryQuotaTracker : IKeyQuotaTracker
{
    // Хранит количество использованных блоков/сообщений для каждого ключа
    private readonly ConcurrentDictionary<Guid, long> _usageCounters = new();

    public void EnsureQuotaAndIncrement(Guid keyId, BelTEncryptionMode mode, long requiredAmount)
    {
        // Определяем лимит согласно Приложению В (СТБ 34.101.31-2020)
        long limit = GetLimitForMode(mode);

        // Атомарно прибавляем requiredAmount к текущему значению
        long currentUsage = _usageCounters.AddOrUpdate(
            keyId,
            requiredAmount,
            (_, existing) => existing + requiredAmount);

        if (currentUsage > limit)
        {
            // Опционально: можно откатить счетчик обратно, если операция заблокирована
            // _usageCounters.AddOrUpdate(keyId, -requiredAmount, (_, existing) => existing - requiredAmount);

            throw new CryptographicException(
                $"Исчерпана криптографическая квота ключа {keyId} для режима {mode}. " +
                $"Лимит: {limit}, Попытка: {currentUsage}. Требуется ротация ключа.");
        }
    }

    public long GetRemainingQuota(Guid keyId, BelTEncryptionMode mode)
    {
        long limit = GetLimitForMode(mode); // Твой switch-case с лимитами
        if (_usageCounters.TryGetValue(keyId, out long usage))
        {
            return Math.Max(0, limit - usage);
        }
        return limit;
    }

    private static long GetLimitForMode(BelTEncryptionMode mode)=> mode switch
        {
            // Не более 2^32 блоков
            BelTEncryptionMode.Ecb or
            BelTEncryptionMode.Cbc or
            BelTEncryptionMode.Cfb or
            BelTEncryptionMode.Dwp => 4_294_967_296L,

            // Не более 2^32 сообщений
            BelTEncryptionMode.Mac => 4_294_967_296L,

            // Для CTR лимит 2^64 блоков. В C# long это 2^63 - 1, 
            // поэтому используем long.MaxValue (на практике этого объема хватит на столетия)
            BelTEncryptionMode.Ctr => long.MaxValue,

            _ => throw new ArgumentOutOfRangeException(nameof(mode))
        };
}
