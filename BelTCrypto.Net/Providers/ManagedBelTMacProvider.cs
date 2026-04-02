using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Providers;

internal sealed class ManagedBelTMacProvider : IManagedBelTMacProvider
{
    private readonly IBelTMac _macCore;
    private readonly IKeyQuotaTracker _quotaTracker;

    public ManagedBelTMacProvider(IBelTMac macCore, IKeyQuotaTracker quotaTracker)
    {
        _macCore = macCore ?? throw new ArgumentNullException(nameof(macCore));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    public void Compute(ReadOnlySpan<byte> data, ISecureCryptoKey key, Span<byte> mac)
    {
        if (mac.Length != 8)
            throw new ArgumentException("Имитовставка belt-mac должна быть ровно 8 байт.", nameof(mac));

        // ВАЖНО: Для MAC инкрементируем квоту на 1 СООБЩЕНИЕ, а не на количество блоков
        EnsureMacIncrement(key.Id);

        Span<byte> rawKey = stackalloc byte[32];
        try
        {
            key.UnmaskInto(rawKey);
            _macCore.Compute(data, rawKey, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ISecureCryptoKey key, ReadOnlySpan<byte> expectedMac)
    {
        if (expectedMac.Length != 8) return false;

        // Проверка квоты также на 1 сообщение
        EnsureMacIncrement(key.Id);

        Span<byte> rawKey = stackalloc byte[32];
        Span<byte> actualMac = stackalloc byte[8];
        try
        {
            key.UnmaskInto(rawKey);
            _macCore.Compute(data, rawKey, actualMac);

            // Используем CryptographicOperations.FixedTimeEquals для предотвращения атак по времени (Timing Attacks)
            // Хотя для имитовставки это менее критично, чем для паролей, это стандарт качества Senior-разработчика
            return CryptographicOperations.FixedTimeEquals(actualMac, expectedMac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
            CryptographicOperations.ZeroMemory(actualMac);
        }
    }

    private void EnsureMacIncrement(Guid keyId)
    {
        try
        {
            _quotaTracker.EnsureQuotaAndIncrement(keyId, BelTEncryptionMode.Mac, 1);
        }
        catch (CryptographicException ex)
        {
            throw new KeyQuotaExceededException(keyId, BelTEncryptionMode.Mac, ex.Message);
        }
    }
}