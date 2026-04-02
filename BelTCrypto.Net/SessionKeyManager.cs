using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public sealed class SessionKeyManager : IDisposable, ISessionKeyManager
{
    private readonly ISecureCryptoKey _masterKey;
    private readonly IBelTKeyService _keyService;

    // Согласно твоему коду Rep(), Заголовок I должен быть 16 байт
    private readonly byte[] _sessionNonce;

    private ulong _rotationCounter; // Счетчик
    private ISecureCryptoKey? _currentWorkingKey;
    private bool _isDisposed;

    public ISecureCryptoKey CurrentKey =>
        _currentWorkingKey ?? throw new InvalidOperationException("Рабочий ключ еще не сгенерирован.");

    public SessionKeyManager(ISecureCryptoKey masterKey, IBelTKeyService keyService, ReadOnlySpan<byte> sessionNonce)
    {
        if (sessionNonce.Length != 16)
            throw new ArgumentException("Session Nonce (Заголовок I) должен быть ровно 16 байт.");

        _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        _keyService = keyService ?? throw new ArgumentNullException(nameof(keyService));
        _sessionNonce = sessionNonce.ToArray();
        _rotationCounter = 0;
        RotateKey();
    }

    public void RotateKey()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        _rotationCounter++;

        // 1. Подготавливаем Уровень D (12 байт). 
        // Записываем наш счетчик в эти 12 байт.
        Span<byte> levelD = stackalloc byte[12];
        levelD.Clear(); // Заполняем нулями
        BinaryPrimitives.WriteUInt64LittleEndian(levelD, _rotationCounter); // Пишем счетчик в начало

        Span<byte> rawMasterKey = stackalloc byte[32];
        Span<byte> rawDerivedKey = stackalloc byte[32];

        try
        {
            // 2. Размаскируем мастер-ключ
            _masterKey.UnmaskInto(rawMasterKey);

            // 3. ВЫЗЫВАЕМ ТВОЙ АЛГОРИТМ BELT-KEYREP
            // x = rawMasterKey
            // d = levelD (12 байт)
            // i = _sessionNonce (16 байт)
            // mBits = 256 (32 байта на выходе)
            _keyService.Rep(rawMasterKey, levelD, _sessionNonce, 256, rawDerivedKey);

            // 4. Обновляем рабочий ключ
            (_currentWorkingKey as IDisposable)?.Dispose();
            _currentWorkingKey = new SecureCryptoKey(rawDerivedKey);
        }
        finally
        {
            // Очистка стека
            CryptographicOperations.ZeroMemory(rawMasterKey);
            CryptographicOperations.ZeroMemory(rawDerivedKey);
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        (_currentWorkingKey as IDisposable)?.Dispose();
        CryptographicOperations.ZeroMemory(_sessionNonce);
        _isDisposed = true;
    }
}