using BelTCrypto.Core.Interfaces.Old;

namespace BelTCrypto.Core.Old;

[Obsolete]
internal sealed class BelTCfbDecryptOldTransform(IBelTBlockOld block, ReadOnlySpan<byte> iv)
    : BelTCfbOldTransform(block, iv)
{
    public override int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        int processed = 0;
        // Выделяем гамму один раз на весь метод
        Span<byte> gamma = stackalloc byte[16];

        while (processed < inputCount)
        {
            // 1. Генерируем ту же гамму (используем Encrypt!)
            _block.Encrypt(_register, gamma);

            // 2. Берем текущий шифртекст (16 байт)
            ReadOnlySpan<byte> currentY = inputBuffer.AsSpan(inputOffset + processed, 16);

            // 3. XOR: Xi = Yi ^ Gamma
            for (int j = 0; j < 16; j++)
            {
                outputBuffer[outputOffset + processed + j] = (byte)(currentY[j] ^ gamma[j]);
            }

            // 4. Обновляем регистр текущим шифртекстом Yi для следующего блока
            // В дешифровании CFB в регистр всегда идет ВХОДНОЙ байт (шифртекст)
            currentY.CopyTo(_register);

            processed += 16;
        }
        return processed;
    }

    public override byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        byte[] output = new byte[inputCount];
        int processed = 0;

        // Выделяем память ОДИН раз на весь метод
        Span<byte> gamma = stackalloc byte[16];

        // 1. Обработка полных блоков
        while (processed + 16 <= inputCount)
        {
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < 16; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // Обновляем регистр входящим шифртекстом (Yi)
            // Используем Span для скорости вместо Array.Copy
            inputBuffer.AsSpan(inputOffset + processed, 16).CopyTo(_register);

            processed += 16;
        }

        // 2. Обработка остатка (Partial block)
        if (processed < inputCount)
        {
            int remaining = inputCount - processed;

            // Используем тот же самый буфер gamma, перевыделять не нужно
            _block.Encrypt(_register, gamma);

            for (int j = 0; j < remaining; j++)
            {
                output[processed + j] = (byte)(inputBuffer[inputOffset + processed + j] ^ gamma[j]);
            }

            // В CFB для неполного блока регистр обычно не обновляется 
            // или обновляется особым образом, но в рамках TransformFinalBlock 
            // это уже не имеет значения, так как это конец данных.
        }

        return output;
    }
}
