using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

internal sealed class SecureCryptoKey : IDisposable, ISecureCryptoKey
{
    public Guid Id { get; }

    private readonly byte[] _maskedKey;
    private readonly byte[] _mask;
    private bool _isDisposed;

    public SecureCryptoKey(ReadOnlySpan<byte> keyMaterial, Guid? id = null)
    {
        if (keyMaterial.Length != 32)
            throw new ArgumentException("Ключ BelT должен быть 256 бит (32 байта).");

        Id = id ?? Guid.NewGuid();

        // GC.AllocateArray с pinned: true доступен с .NET 5.
        // Это гарантирует, что массив не будет перемещаться в памяти сборщиком мусора.
        _maskedKey = GC.AllocateArray<byte>(keyMaterial.Length, pinned: true);
        _mask = GC.AllocateArray<byte>(keyMaterial.Length, pinned: true);

        // Генерируем криптостойкую случайную маску
        RandomNumberGenerator.Fill(_mask);

        // Накладываем маску на ключ (XOR) в момент создания
        for (int i = 0; i < keyMaterial.Length; i++)
        {
            _maskedKey[i] = (byte)(keyMaterial[i] ^ _mask[i]);
        }
    }

    /// <summary>
    /// Безопасный доступ к ключу через scoped-вызов.
    /// Ключ существует в открытом виде только внутри этого делегата (в стеке).
    /// </summary>
    public void UseKey(Action<ReadOnlySpan<byte>> cryptoOperation)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);

        // Выделяем память под реальный ключ ТОЛЬКО на стеке (не попадает в кучу)
        Span<byte> rawKey = stackalloc byte[_maskedKey.Length];

        try
        {
            // Снимаем маску (XOR)
            for (int i = 0; i < _maskedKey.Length; i++)
            {
                rawKey[i] = (byte)(_maskedKey[i] ^ _mask[i]);
            }

            // Выполняем полезную нагрузку (шифрование/дешифрование)
            cryptoOperation(rawKey);
        }
        finally
        {
            // ГАРАНТИРОВАННО затираем ключ на стеке сразу после использования
            CryptographicOperations.ZeroMemory(rawKey);
        }
    }

    public void UnmaskInto(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
        if (destination.Length != _maskedKey.Length)
            throw new ArgumentException($"Размер буфера должен быть {_maskedKey.Length} байт.");

        for (int i = 0; i < _maskedKey.Length; i++)
            destination[i] = (byte)(_maskedKey[i] ^ _mask[i]);
    }

    public void Dispose()
    {
        if (_isDisposed) return;

        // Затираем Pinned массивы при уничтожении объекта
        CryptographicOperations.ZeroMemory(_maskedKey);
        CryptographicOperations.ZeroMemory(_mask);

        _isDisposed = true;
    }
}