using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal sealed class BelTCfbEncryptTransform(IBelTBlock block, ReadOnlySpan<byte> iv)
    : BelTCfbTransform(block, iv)
{
    public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int processed = 0;
        while (processed < inputCount)
        {
            // 1. Генерируем гамму: Encrypt(Yi-1)
            Span<byte> gamma = stackalloc byte[16];
            _block.Encrypt(_register, gamma);

            // 2. XOR: Yi = Xi ^ Gamma
            for (int j = 0; j < 16; j++)
            {
                outputBuffer[outputOffset + processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // 3. Обновляем регистр: Yi-1 = Yi
            Array.Copy(outputBuffer, outputOffset + processed, _register, 0, 16);

            processed += 16;
        }
        return processed;
    }

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] output = new byte[inputCount];
        int processed = 0;

        // Цикл по всем полным блокам, если они есть
        while (processed + 16 <= inputCount)
        {
            Span<byte> gamma = stackalloc byte[16];
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < 16; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // Обновляем регистр текущим результатом (Yi)
            Array.Copy(output, processed, _register, 0, 16);
            processed += 16;
        }

        // Обработка последнего неполного блока (хвоста)
        if (processed < inputCount)
        {
            int remaining = inputCount - processed;
            Span<byte> gamma = stackalloc byte[16];
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < remaining; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }
        }

        return output;
    }
}
