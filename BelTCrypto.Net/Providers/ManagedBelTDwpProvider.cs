using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Providers;

internal sealed class ManagedBelTDwpProvider : IManagedBelTDwpProvider
{
    private readonly IBelTDwp _dwpCore;
    private readonly IKeyQuotaTracker _quotaTracker;

    public ManagedBelTDwpProvider(IBelTDwp dwpCore, IKeyQuotaTracker quotaTracker)
    {
        _dwpCore = dwpCore ?? throw new ArgumentNullException(nameof(dwpCore));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    public void Protect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output, Span<byte> tag)
    {
        if (iv.Length != 16) throw new ArgumentException("IV должен быть 16 байт.");
        if (tag.Length != 8) throw new ArgumentException("Tag должен быть 8 байт.");

        // 1. Считаем суммарную квоту согласно стандарту
        long adBlocks = (ad.Length + 15) / 16;
        long dataBlocks = (data.Length + 15) / 16;
        EnsureQuotaUpdate(key.Id, adBlocks + dataBlocks);

        Span<byte> rawKey = stackalloc byte[32];
        try
        {
            key.UnmaskInto(rawKey);
            _dwpCore.Protect(data, ad, iv, rawKey, output, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public bool Unprotect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output, ReadOnlySpan<byte> expectedTag)
    {
        if (iv.Length != 16 || expectedTag.Length != 8) return false;

        // Квота проверяется и при дешифровании
        long adBlocks = (ad.Length + 15) / 16;
        long dataBlocks = (data.Length + 15) / 16;
        EnsureQuotaUpdate(key.Id, adBlocks + dataBlocks);

        Span<byte> rawKey = stackalloc byte[32];
        Span<byte> actualTag = stackalloc byte[8];
        try
        {
            key.UnmaskInto(rawKey);

            // Сначала расшифровываем и вычисляем тег
            _dwpCore.Unprotect(data, ad, iv, rawKey, output, actualTag);

            // Безопасное сравнение тега (защита от Timing Attacks)
            if (!CryptographicOperations.FixedTimeEquals(actualTag, expectedTag))
            {
                output.Clear(); // Затираем мусор в output, если проверка не прошла
                return false;
            }

            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
            CryptographicOperations.ZeroMemory(actualTag);
        }
    }

    private void EnsureQuotaUpdate(Guid keyId, long blocksToAdd)
    {
        try
        {
            _quotaTracker.EnsureQuotaAndIncrement(keyId, BelTEncryptionMode.Dwp, blocksToAdd);
        }
        catch (KeyQuotaExceededException ex)
        {
            // Здесь можно добавить логирование или другую обработку исключения
            throw new KeyQuotaExceededException(keyId, BelTEncryptionMode.Dwp, ex.Message);
        }
    }
}