using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal sealed class BelTCfbDecryptTransform(IBelTBlock block, ReadOnlySpan<byte> iv)
    : BelTCfbTransform(block, iv)
{
    public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int processed = 0;
        while (processed < inputCount)
        {
            // 1. Генерируем ту же гамму (используем Encrypt!)
            Span<byte> gamma = stackalloc byte[16];
            _block.Encrypt(_register, gamma);

            // 2. Сохраняем текущий шифртекст для следующего шага
            // Делаем это ДО XOR, так как регистр должен содержать Yi
            Span<byte> currentY = inputBuffer.AsSpan(inputOffset + processed, 16);

            // 3. XOR: Xi = Yi ^ Gamma
            for (int j = 0; j < 16; j++)
            {
                outputBuffer[outputOffset + processed + j] = (byte)(currentY[j] ^ gamma[j]);
            }

            // 4. Обновляем регистр текущим шифртекстом
            currentY.CopyTo(_register);

            processed += 16;
        }
        return processed;
    }

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] output = new byte[inputCount];
        int processed = 0;

        while (processed + 16 <= inputCount)
        {
            Span<byte> gamma = stackalloc byte[16];
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < 16; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // В дешифровании регистр обновляется входящим шифртекстом (Yi)
            Array.Copy(inputBuffer, inputOffset + processed, _register, 0, 16);
            processed += 16;
        }

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
