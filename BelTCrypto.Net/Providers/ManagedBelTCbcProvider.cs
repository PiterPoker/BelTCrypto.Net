using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Providers;

internal sealed class ManagedBelTCbcProvider : IManagedBelTCbcProvider
{
    private readonly IBelTCbc _cbcCore; // Предполагается, что интерфейс ядра уже существует
    private readonly IKeyQuotaTracker _quotaTracker;

    public ManagedBelTCbcProvider(IBelTCbc cbcCore, IKeyQuotaTracker quotaTracker)
    {
        _cbcCore = cbcCore ?? throw new ArgumentNullException(nameof(cbcCore));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    public void Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output)
    {
        if (data.Length == 0) return;

        // ВАЖНО: Защита от дурака. Синхропосылка должна быть ровно один блок.
        if (iv.Length != 16)
            throw new ArgumentException("Вектор инициализации (IV) для belt-cbc должен быть 16 байт (128 бит).", nameof(iv));

        // 1. Расчет необходимых блоков (кража шифротекста в CBC работает так же)
        long blocksCount = (data.Length + 15) / 16;

        // 2. Проверка и захват квоты (лимит 2^32 блоков)
        EnsureQuotaUpdate(key.Id, blocksCount);

        // 3. Выделение памяти под чистый ключ строго на стеке
        Span<byte> rawKey = stackalloc byte[32];

        try
        {
            // 4. Размаскировка ключа
            key.UnmaskInto(rawKey);

            // 5. Вызов математического ядра с передачей IV
            _cbcCore.Encrypt(data, iv, rawKey, output);
        }
        finally
        {
            // 6. Гарантированное уничтожение чистого ключа
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public void Decrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output)
    {
        if (data.Length == 0) return;
        if (iv.Length != 16)
            throw new ArgumentException("Вектор инициализации (IV) для belt-cbc должен быть 16 байт (128 бит).", nameof(iv));

        long blocksCount = (data.Length + 15) / 16;
        EnsureQuotaUpdate(key.Id, blocksCount);

        Span<byte> rawKey = stackalloc byte[32];
        try
        {
            key.UnmaskInto(rawKey);
            _cbcCore.Decrypt(data, iv, rawKey, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    private void EnsureQuotaUpdate(Guid keyId, long blocksToProcess)
    {
        try
        {
            _quotaTracker.EnsureQuotaAndIncrement(keyId, BelTEncryptionMode.Cbc, blocksToProcess);
        }
        catch (KeyQuotaExceededException ex)
        {
            // Здесь можно добавить логирование или другую обработку исключения
            throw new KeyQuotaExceededException(keyId, BelTEncryptionMode.Cbc, ex.Message);
        }
    }
}
