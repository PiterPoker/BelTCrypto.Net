using BelTCrypto.Core.Interfaces.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Old;

internal sealed class BelTCtrOldTransform : IBelTCrtOldTransform
{
    private readonly IBelTBlockOld _block;
    private readonly byte[] _s = new byte[16]; // Регистр счетчика s
    private bool _isDisposed;

    public BelTCtrOldTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
        if (iv.Length != 16) throw new ArgumentException("S (IV) must be 128 bits");

        // СТБ Шаг 2: s = belt-block(S, K)
        // Предварительное зашифрование синхропосылки
        _block.Encrypt(iv, _s);
    }

    public int InputBlockSize => 16;
    public int OutputBlockSize => 16;
    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => false;

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int processed = 0;
        Span<byte> gamma = stackalloc byte[16];

        while (processed < inputCount)
        {
            // Шаг 3.1: s = s + 1 (mod 2^128)
            IncrementCounter();

            // Шаг 3.2: Генерируем гамму
            _block.Encrypt(_s, gamma);

            for (int i = 0; i < 16; i++)
            {
                outputBuffer[outputOffset + processed + i] = (byte)(inputBuffer[inputOffset + processed + i] ^ gamma[i]);
            }
            processed += 16;
        }
        return processed;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] output = new byte[inputCount];
        int processed = 0;
        Span<byte> gamma = stackalloc byte[16];

        // Полные блоки
        while (processed + 16 <= inputCount)
        {
            IncrementCounter();
            _block.Encrypt(_s, gamma);
            for (int j = 0; j < 16; j++)
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            processed += 16;
        }

        // Хвост (Lo)
        if (processed < inputCount)
        {
            IncrementCounter();
            _block.Encrypt(_s, gamma);
            int remaining = inputCount - processed;
            for (int j = 0; j < remaining; j++)
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
        }
        return output;
    }

    private void IncrementCounter()
    {
        // 128-битный инкремент (Little-endian порядок согласно СТБ)
        for (int i = 0; i < 16; i++)
        {
            if (++_s[i] != 0) break;
        }
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        CryptographicOperations.ZeroMemory(_s);
        _block.Dispose();
        _isDisposed = true;
    }
}