using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTEcb : IBelTEcb
{
    private IBelTBlock _block;

    public BelTEcb(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, Span<byte> y)
    {
        int totalLen = x.Length;
        if (totalLen < 16) throw new ArgumentException("X должен быть >= 128 бит.");

        int n = (totalLen + 15) / 16;
        int mBytes = totalLen % 16;

        if (mBytes == 0)
        {
            for (int i = 0; i < n; i++)
            {
                _block.Encrypt(x.Slice(i * 16, 16), k, y.Slice(i * 16, 16));
            }
        }
        else
        {
            // 1) Yi ← belt-block(Xi, K) для i = 1...n-2
            for (int i = 0; i < n - 2; i++)
            {
                _block.Encrypt(x.Slice(i * 16, 16), k, y.Slice(i * 16, 16));
            }

            int idxPrev = (n - 2) * 16;
            int idxLast = (n - 1) * 16;

            // 2) (Yn ‖ r) ← belt-block(Xn-1, K)
            Span<byte> rWithYn = stackalloc byte[16];
            try
            {
                _block.Encrypt(x.Slice(idxPrev, 16), k, rWithYn);
                rWithYn[..mBytes].CopyTo(y.Slice(idxLast, mBytes));
                ReadOnlySpan<byte> r = rWithYn[mBytes..];

                // 3) Yn-1 ← belt-block(Xn ‖ r, K)
                Span<byte> xnWithR = stackalloc byte[16];
                try
                {
                    x.Slice(idxLast, mBytes).CopyTo(xnWithR);
                    r.CopyTo(xnWithR[mBytes..]);
                    _block.Encrypt(xnWithR, k, y.Slice(idxPrev, 16));
                }
                finally
                {
                    xnWithR.Clear();
                }
            }
            finally
            {
                rWithYn.Clear();
            }
        }
    }

    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, Span<byte> x)
    {
        // 1) Определить (Y1, Y2, ..., Yn) = Split(Y, 128)
        int totalLen = y.Length;
        if (totalLen < 16) throw new ArgumentException("Y должен быть >= 128 бит.");

        int n = (totalLen + 15) / 16;
        int mBytes = totalLen % 16;

        // 2) Если |Yn| = 128
        if (mBytes == 0)
        {
            for (int i = 0; i < n; i++)
            {
                _block.Decrypt(y.Slice(i * 16, 16), k, x.Slice(i * 16, 16));
            }
        }
        // 3) Иначе, если |Yn| < 128
        else
        {
            // 1) Xi ← belt-block−1(Yi, K) для i = 1...n-2
            for (int i = 0; i < n - 2; i++)
            {
                _block.Decrypt(y.Slice(i * 16, 16), k, x.Slice(i * 16, 16));
            }

            int idxPrev = (n - 2) * 16;
            int idxLast = (n - 1) * 16;

            Span<byte> xnWithR = stackalloc byte[16];
            try
            {
                // 2) (Xn ‖ r) ← belt-block−1(Yn−1, K)
                _block.Decrypt(y.Slice(idxPrev, 16), k, xnWithR);
                xnWithR[..mBytes].CopyTo(x.Slice(idxLast, mBytes));
                ReadOnlySpan<byte> r = xnWithR[mBytes..];

                Span<byte> ynWithR = stackalloc byte[16];
                try
                {
                    // 3) Xn−1 ← belt-block−1(Yn ‖ r, K)
                    y.Slice(idxLast, mBytes).CopyTo(ynWithR);
                    r.CopyTo(ynWithR[mBytes..]);
                    _block.Decrypt(ynWithR, k, x.Slice(idxPrev, 16));
                }
                finally 
                { 
                    ynWithR.Clear(); 
                }
            }
            finally 
            { 
                xnWithR.Clear(); 
            }
        }
    }
}
