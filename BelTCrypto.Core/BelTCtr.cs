using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTCtr : IBelTCtr
{
    private readonly IBelTBlock _block;
    public BelTCtr(IBelTBlock block)
    {
        _block = block;
    }

    public void Process(ReadOnlySpan<byte> data, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> result)
    {
        int totalLen = data.Length;
        int n = (totalLen + 15) / 16;

        // 2) Установить s = belt-block(S, K)
        Span<byte> stateS = stackalloc byte[16];
        _block.Encrypt(s, k, stateS);

        Span<byte> wGamma = stackalloc byte[16];

        try
        {
            // 3) Для i = 1, 2, ..., n выполнить:
            for (int i = 0; i < n; i++)
            {
                int offset = i * 16;
                int blockSize = Math.Min(16, totalLen - offset);

                var inputBlock = data.Slice(offset, blockSize);
                var outputBlock = result.Slice(offset, blockSize);

                // 3.1) s = s + 1 (mod 2^128)
                // Используем твой инкремент из BelTMath.Block
                BelTMath.Block.Increment(stateS);

                // 3.2) Yi = Xi ^ Lo(belt-block(s, K), |Xi|)
                _block.Encrypt(stateS, k, wGamma);

                // Копируем вход в выход и применяем XOR гаммы
                inputBlock.CopyTo(outputBlock);
                BelTMath.GfBlock.Xor(outputBlock, wGamma, blockSize);
            }

            // 4) Возвратить Y = Y1 || Y2 || ... || Yn (уже в Span result)
        }
        finally
        {
            // Стерилизация стека
            stateS.Clear();
            wGamma.Clear();
        }
    }
}
