using BelTCrypto.Core.Abstractions;
using BelTCrypto.Core.Interfaces.Old;

namespace BelTCrypto.Core;

internal sealed class BelTCfbEncryptTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv)
    : BelTCfbTransform(block, iv)
{
    public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int processed = 0;
        Span<byte> gamma = stackalloc byte[16];

        while (processed < inputCount)
        {
            _block.Encrypt(_register, gamma);

            // Работаем со слайсами для чистоты кода
            ReadOnlySpan<byte> input = inputBuffer.AsSpan(inputOffset + processed, 16);
            Span<byte> output = outputBuffer.AsSpan(outputOffset + processed, 16);

            for (int j = 0; j < 16; j++)
            {
                output[j] = (byte)(input[j] ^ gamma[j]);
            }

            // Обновляем регистр напрямую из output
            output.CopyTo(_register);

            processed += 16;
        }
        return processed;
    }

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] output = new byte[inputCount];
        int processed = 0;

        // 1. Выносим выделение памяти из цикла.
        // Теперь, сколько бы блоков ни было, мы используем одни и те же 16 байт в стеке.
        Span<byte> gamma = stackalloc byte[16];

        // Цикл по всем полным блокам
        while (processed + 16 <= inputCount)
        {
            // Используем заранее выделенный буфер
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < 16; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // В шифровании CFB регистр обновляется ВЫХОДОМ (шифртекстом Yi)
            // Используем Span для быстрого копирования
            output.AsSpan(processed, 16).CopyTo(_register);

            processed += 16;
        }

        // 2. Обработка последнего неполного блока (хвоста)
        if (processed < inputCount)
        {
            int remaining = inputCount - processed;

            // Используем тот же самый буфер gamma
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < remaining; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // Для неполного блока в режиме CFB (согласно СТБ) регистр 
            // обычно не обновляется, так как цепочка прерывается.
        }

        return output;
    }
}
