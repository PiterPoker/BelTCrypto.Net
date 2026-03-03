using BelTCrypto.Core;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public class BelTTransform : ICryptoTransform
{
    private readonly BelTWideBlock _wideBlock;
    private readonly bool _encrypting;
    private bool _disposed;

    public BelTTransform(byte[] key, bool encrypting)
    {
        var engine = new BelTBlock(key);
        _wideBlock = new BelTWideBlock(engine);
        _encrypting = encrypting;
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        var input = inputBuffer.AsSpan(inputOffset, inputCount);
        var output = outputBuffer.AsSpan(outputOffset, inputCount);

        if (_encrypting)
            _wideBlock.Encrypt(input, output);
        else
            _wideBlock.Decrypt(input, output);

        return inputCount;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        if (inputCount == 0) return [];

        byte[] result = new byte[inputCount];
        var input = inputBuffer.AsSpan(inputOffset, inputCount);

        if (_encrypting)
            _wideBlock.Encrypt(input, result);
        else
            _wideBlock.Decrypt(input, result);

        return result;
    }

    public int InputBlockSize => 16;
    public int OutputBlockSize => 16;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => true;

    public void Dispose() 
    {
        _wideBlock?.Dispose();
        _disposed = true;
    }
}
