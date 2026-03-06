using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Abstractions;

internal abstract class BelTCfbTransform : IBelTCfbTransform
{
    protected readonly IBelTBlock _block;
    protected readonly byte[] _register = new byte[16]; // Это наше Yi-1 (или S в начале)
    protected bool _isDisposed;

    protected BelTCfbTransform(IBelTBlock block, ReadOnlySpan<byte> iv)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
        if (iv.Length != 16) throw new ArgumentException("IV (S) must be 128 bits");
        iv.CopyTo(_register);
    }

    public int InputBlockSize => 16;
    public int OutputBlockSize => 16;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => false;

    public abstract int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);
    public abstract byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);

    public void Dispose()
    {
        if (_isDisposed) return;
        CryptographicOperations.ZeroMemory(_register);
        _block.Dispose();
        _isDisposed = true;
    }
}