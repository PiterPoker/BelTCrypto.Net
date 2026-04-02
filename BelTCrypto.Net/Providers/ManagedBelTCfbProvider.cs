using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Providers;

internal sealed class ManagedBelTCfbProvider : IManagedBelTCfbProvider
{
    private readonly IBelTCfb _cfbCore;
    private readonly IKeyQuotaTracker _quotaTracker;

    public ManagedBelTCfbProvider(IBelTCfb cfbCore, IKeyQuotaTracker quotaTracker)
    {
        _cfbCore = cfbCore ?? throw new ArgumentNullException(nameof(cfbCore));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    public void Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output)
    {
        if (data.Length == 0) return;

        // IV для базового режима CFB в СТБ 34.101.31-2020 равен 128 бит (16 байт)
        if (iv.Length != 16)
            throw new ArgumentException("Вектор инициализации (IV) для belt-cfb должен быть 16 байт.", nameof(iv));

        if (output.Length < data.Length)
            throw new ArgumentException("Выходной буфер слишком мал.", nameof(output));

        // Расчет квоты: один вызов блочного шифра тратится на каждые начатые 16 байт
        long blocksCount = (data.Length + 15) / 16;

        // Захват квоты
        _quotaTracker.EnsureQuotaAndIncrement(key.Id, BelTEncryptionMode.Cfb, blocksCount);

        Span<byte> rawKey = stackalloc byte[32];

        try
        {
            key.UnmaskInto(rawKey);
            _cfbCore.Encrypt(data, iv, rawKey, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public void Decrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output)
    {
        if (data.Length == 0) return;

        if (iv.Length != 16)
            throw new ArgumentException("Вектор инициализации (IV) для belt-cfb должен быть 16 байт.", nameof(iv));

        if (output.Length < data.Length)
            throw new ArgumentException("Выходной буфер слишком мал.", nameof(output));

        long blocksCount = (data.Length + 15) / 16;

        _quotaTracker.EnsureQuotaAndIncrement(key.Id, BelTEncryptionMode.Cfb, blocksCount);

        Span<byte> rawKey = stackalloc byte[32];

        try
        {
            key.UnmaskInto(rawKey);
            _cfbCore.Decrypt(data, iv, rawKey, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }
}