using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Providers;

internal sealed class ManagedBelTEcbProvider : IManagedBelTEcbProvider
{
    private readonly IBelTEcb _ecbCore;
    private readonly IKeyQuotaTracker _quotaTracker;

    public ManagedBelTEcbProvider(IBelTEcb ecbCore, IKeyQuotaTracker quotaTracker)
    {
        _ecbCore = ecbCore ?? throw new ArgumentNullException(nameof(ecbCore));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    public void Encrypt(ReadOnlySpan<byte> data, ISecureCryptoKey key, Span<byte> output)
    {
        if (data.Length == 0) return;

        // 1. Расчет необходимых блоков (с округлением вверх)
        long blocksCount = (data.Length + 15) / 16;

        // 2. Проверка и захват квоты (выбросит исключение, если лимит превышен)
        EnsureQuotaUpdate(key.Id, blocksCount);

        // 3. Выделение памяти под чистый ключ строго на стеке
        Span<byte> rawKey = stackalloc byte[32];

        try
        {
            // 4. Размаскировка ключа в стек
            key.UnmaskInto(rawKey);

            // 5. Вызов математического ядра (без аллокаций памяти в куче!)
            _ecbCore.Encrypt(data, rawKey, output);
        }
        finally
        {
            // 6. Гарантированное уничтожение чистого ключа в памяти
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public void Decrypt(ReadOnlySpan<byte> data, ISecureCryptoKey key, Span<byte> output)
    {
        long blocksCount = (data.Length + 15) / 16;

        // При дешифровании квота ключа также расходуется!
        EnsureQuotaUpdate(key.Id, blocksCount);

        Span<byte> rawKey = stackalloc byte[32];
        try
        {
            key.UnmaskInto(rawKey);
            _ecbCore.Decrypt(data, rawKey, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    private void EnsureQuotaUpdate(Guid keyId, long blocksToAdd)
    {
        try
        {
            _quotaTracker.EnsureQuotaAndIncrement(keyId, BelTEncryptionMode.Ecb, blocksToAdd);
        }
        catch (KeyQuotaExceededException ex)
        {
            // Логирование или дополнительная обработка при превышении квоты
            // Например, можно добавить информацию о том, сколько блоков было запрошено и сколько осталось
            throw new KeyQuotaExceededException(keyId, BelTEncryptionMode.Ecb, ex.Message);
        }
    }
}