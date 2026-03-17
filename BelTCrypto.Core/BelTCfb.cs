using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTCfb: IBelTCfb
{
    private readonly IBelTBlock _block;
    public BelTCfb(IBelTBlock block) => _block = block ?? throw new ArgumentNullException(nameof(block));

    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x)
    {
        int totalLen = y.Length;
        int n = (totalLen + 15) / 16;

        Span<byte> feedback = stackalloc byte[16];
        s.CopyTo(feedback);
        Span<byte> gamma = stackalloc byte[16];
        Span<byte> currentYi = stackalloc byte[16];

        try
        {
            for (int i = 0; i < n; i++)
            {
                int offset = i * 16;
                int blockSize = Math.Min(16, totalLen - offset);

                var yi = y.Slice(offset, blockSize);
                var xi = x.Slice(offset, blockSize);

                // ЗАЩИТА IN-PLACE: сохраняем шифртекст до того, как XOR изменит xi
                yi.CopyTo(currentYi);

                // 1. Wi = belt-block(Yi-1, K)
                _block.Encrypt(feedback, k, gamma);

                // 2. Xi = Yi ^ Lo(Wi, |Yi|)
                yi.CopyTo(xi);
                BelTMath.GfBlock.Xor(xi, gamma, blockSize);

                // 3. Обновление обратной связи (Feedback = сохраненный шифртекст)
                if (i < n - 1)
                    currentYi.CopyTo(feedback);
            }
        }
        finally
        {
            feedback.Clear();
            gamma.Clear();
            currentYi.Clear();
        }
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y)
    {
        int totalLen = x.Length;
        int n = (totalLen + 15) / 16;

        Span<byte> rRegister = stackalloc byte[16];
        s.CopyTo(rRegister);
        Span<byte> wGamma = stackalloc byte[16];

        try
        {
            for (int i = 0; i < n; i++)
            {
                int offset = i * 16;
                int blockSize = Math.Min(16, totalLen - offset);

                var xi = x.Slice(offset, blockSize);
                var yi = y.Slice(offset, blockSize);

                // 1) Wi = belt-block(Yi-1, K)
                _block.Encrypt(rRegister, k, wGamma);

                // 2) Yi = Xi ^ Lo(Wi, |Xi|) 
                xi.CopyTo(yi);
                BelTMath.GfBlock.Xor(yi, wGamma, blockSize);

                // 3) Обновление обратной связи
                if (i < n - 1)
                    yi.CopyTo(rRegister);
            }
        }
        finally
        {
            rRegister.Clear();
            wGamma.Clear();
        }
    }
}
