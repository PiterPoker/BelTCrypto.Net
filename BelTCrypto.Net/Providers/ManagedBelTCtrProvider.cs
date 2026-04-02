using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Providers;

internal sealed class ManagedBelTCtrProvider : IManagedBelTCtrProvider
{
    private readonly IBelTCtr _ctrCore;
    private readonly IKeyQuotaTracker _quotaTracker;

    public ManagedBelTCtrProvider(IBelTCtr ctrCore, IKeyQuotaTracker quotaTracker)
    {
        _ctrCore = ctrCore ?? throw new ArgumentNullException(nameof(ctrCore));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    public void Process(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output)
    {
        if (data.Length == 0) return;

        // Синхропосылка для CTR должна быть 16 байт
        if (iv.Length != 16)
            throw new ArgumentException("Вектор инициализации (IV) для belt-ctr должен быть 16 байт.", nameof(iv));

        if (output.Length < data.Length)
            throw new ArgumentException("Выходной буфер слишком мал.", nameof(output));

        // Для генерации гаммы ядро будет вызывать блочный шифр с округлением вверх
        long blocksCount = (data.Length + 15) / 16;

        // Захват квоты (лимит 2^64 блоков)
        EnsureQuotaUpdate(key.Id, blocksCount);

        Span<byte> rawKey = stackalloc byte[32];

        try
        {
            key.UnmaskInto(rawKey);
            _ctrCore.Process(data, iv, rawKey, output);
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
            _quotaTracker.EnsureQuotaAndIncrement(keyId, BelTEncryptionMode.Ctr, blocksToProcess);
        }
        catch (KeyQuotaExceededException ex)
        {
            // Здесь можно добавить логирование или другую обработку исключения
            throw new KeyQuotaExceededException(keyId, BelTEncryptionMode.Ctr, ex.Message);
        }
    }
}
