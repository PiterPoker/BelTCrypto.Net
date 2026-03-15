using BelTCrypto.Core.Interfaces;
using BelTCrypto.Core.Interfaces.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Abstractions;

internal abstract class BelTCbcTransform : IBelTCbcTransform
{
    protected readonly IBelTBlockOld _block;
    protected readonly byte[] _prevY;
    protected readonly byte[] _buffer;
    protected int _bufferCount;
    protected bool _isDisposed;

    protected BelTCbcTransform(IBelTBlockOld block, ReadOnlySpan<byte> s)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
        _prevY = s.ToArray();
        _buffer = new byte[16];
        _bufferCount = 0;
    }

    // Общий Dispose для обоих направлений
    public void Dispose()
    {
        if (_isDisposed) return;
        try
        {
            CryptographicOperations.ZeroMemory(_buffer);
            CryptographicOperations.ZeroMemory(_prevY);
            _block?.Dispose();
        }
        finally { _isDisposed = true; }
    }

    // Общие свойства
    public int InputBlockSize => 16;
    public int OutputBlockSize => 16;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => false;

    // Методы, которые каждый реализует по-своему
    public abstract int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);
    public abstract byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);

    protected static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> res)
    {
        for (int i = 0; i < 16; i++) res[i] = (byte)(a[i] ^ b[i]);
    }
}
