using System.Security.Cryptography;

namespace BelTCrypto.Core.Interfaces.Old;

internal abstract class BelTEcbTransformOld(IBelTBlockOld block) : IBelTEcbTransformOld
{
    protected readonly IBelTBlockOld _block = block ?? throw new ArgumentNullException(nameof(block));
    protected readonly byte[] _buffer = new byte[16];
    protected int _bufferCount = 0;
    protected bool _isDisposed;

    public int InputBlockSize => 16;
    public int OutputBlockSize => 16;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => false;

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (!_isDisposed)
        {
            int totalProcessed = 0;
            int currentPos = inputOffset;
            int remaining = inputCount;

            // Если в буфере уже есть данные, и пришли новые — значит данные в буфере точно не последние
            if (_bufferCount == 16 && remaining > 0)
            {
                ProcessBlock(_buffer, outputBuffer.AsSpan(outputOffset, 16));
                totalProcessed += 16;
                _bufferCount = 0;
            }

            // Обрабатываем входящие блоки, всегда оставляя последний блок (или его часть) в буфере
            while (remaining > 16)
            {
                ProcessBlock(inputBuffer.AsSpan(currentPos, 16), outputBuffer.AsSpan(outputOffset + totalProcessed, 16));
                currentPos += 16;
                remaining -= 16;
                totalProcessed += 16;
            }

            // Сохраняем остаток в буфер
            if (remaining > 0)
            {
                Array.Copy(inputBuffer, currentPos, _buffer, _bufferCount, remaining);
                _bufferCount += remaining;
            }

            return totalProcessed;
        }

        throw new ObjectDisposedException(nameof(BelTEcbTransformOld));
    }

    public abstract byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
    protected abstract void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output);

    public void Dispose()
    {
        if (_isDisposed) return;
        CryptographicOperations.ZeroMemory(_buffer);
        _block?.Dispose();
        _isDisposed = true;
    }
}