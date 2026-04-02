using BelTCrypto.Net.Interfaces;
using BelTCrypto.Net.Providers;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Services;

public sealed class BelTEcbCryptoService
{
    private readonly ISessionKeyManager _sessionManager;
    private readonly IManagedBelTEcbProvider _ecbProvider;
    private readonly IKeyQuotaTracker _quotaTracker;

    // Событие для уведомления вызывающего кода о том, что произошла ротация.
    // Это критично для записи маркеров в файл или поток.
    public event Action<uint>? OnKeyRotated;

    public BelTEcbCryptoService(
        ISessionKeyManager sessionManager,
        IManagedBelTEcbProvider ecbProvider,
        IKeyQuotaTracker quotaTracker)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _ecbProvider = ecbProvider ?? throw new ArgumentNullException(nameof(ecbProvider));
        _quotaTracker = quotaTracker ?? throw new ArgumentNullException(nameof(quotaTracker));
    }

    /// <summary>
    /// Шифрует данные с автоматическим контролем квот и ротацией ключей.
    /// </summary>
    public void Encrypt(ReadOnlySpan<byte> data, Span<byte> output, bool autoRotate = true)
    {
        ProcessData(data, output, isEncryption: true, autoRotate);
    }

    /// <summary>
    /// Дешифрует данные.
    /// </summary>
    public void Decrypt(ReadOnlySpan<byte> data, Span<byte> output, bool autoRotate = true)
    {
        ProcessData(data, output, isEncryption: false, autoRotate);
    }

    private void ProcessData(ReadOnlySpan<byte> data, Span<byte> output, bool isEncryption, bool autoRotate)
    {
        int offset = 0;
        int remainingBytes = data.Length;

        while (remainingBytes > 0)
        {
            var currentKey = _sessionManager.CurrentKey;

            // 1. Узнаем остаток квоты в блоках (1 блок = 16 байт)
            long remainingBlocks = _quotaTracker.GetRemainingQuota(currentKey.Id, BelTEncryptionMode.Ecb);

            if (remainingBlocks <= 0)
            {
                if (!autoRotate) throw new CryptographicException("Квота ключа исчерпана.");

                HandleRotation();
                continue; // Начинаем цикл заново с новым ключом
            }

            // 2. Рассчитываем, сколько байт мы можем обработать текущим ключом
            // Мы должны резать строго по границе блоков (16 байт)
            long maxBytesByQuota = remainingBlocks * 16;
            int bytesToProcess = (int)Math.Min(remainingBytes, maxBytesByQuota);

            // 3. Если мы не на последнем куске данных и квота заставляет нас резать,
            // убеждаемся, что мы режем по 16 байт (граница блока ECB)
            if (bytesToProcess < remainingBytes)
            {
                bytesToProcess = (bytesToProcess / 16) * 16;
                if (bytesToProcess == 0) // Квоты не хватает даже на один блок
                {
                    HandleRotation();
                    continue;
                }
            }

            // 4. Выполняем операцию
            if (isEncryption)
                _ecbProvider.Encrypt(data.Slice(offset, bytesToProcess), currentKey, output.Slice(offset, bytesToProcess));
            else
                _ecbProvider.Decrypt(data.Slice(offset, bytesToProcess), currentKey, output.Slice(offset, bytesToProcess));

            offset += bytesToProcess;
            remainingBytes -= bytesToProcess;

            // 5. Если квота была заполнена «под завязку», ротируем ключ для следующей итерации
            if (remainingBytes > 0 && _quotaTracker.GetRemainingQuota(currentKey.Id, BelTEncryptionMode.Ecb) == 0)
            {
                if (!autoRotate) throw new CryptographicException("Квота ключа исчерпана.");
                HandleRotation();
            }
        }
    }

    private void HandleRotation()
    {
        _sessionManager.RotateKey();

        // В SessionKeyManager мы инкрементируем счетчик. 
        // Здесь мы можем пробросить событие наверх, чтобы записать маркер в файл.
        //OnKeyRotated?.Invoke(_sessionManager.RotationCounter); 
    }
}