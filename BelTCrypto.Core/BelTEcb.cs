using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTEcb : IBelTEcb
{
    private readonly IBelTBlock _block;

    public BelTEcb(IBelTBlock block) => _block = block ?? throw new ArgumentNullException(nameof(block));

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, Span<byte> y)
    {

        if (x.Length < 16) throw new ArgumentException("Длина данных должна быть >= 128 бит.");
        int n = (x.Length + 15) / 16;
        int mBytes = x.Length % 16;

        if (mBytes == 0)
        {
            EncryptFullBlocks(x, y, k, n);
        }
        else
        {
            EncryptFullBlocks(x, y, k, n - 2);
            FinalizeEncryption(x, y, k, n, mBytes);
        }
    }

    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, Span<byte> x)
    {

        if (y.Length < 16) throw new ArgumentException("Длина данных должна быть >= 128 бит.");
        int n = (y.Length + 15) / 16;
        int mBytes = y.Length % 16;

        if (mBytes == 0)
        {
            DecryptFullBlocks(y, x, k, n);
        }
        else
        {
            DecryptFullBlocks(y, x, k, n - 2);
            FinalizeDecryption(y, x, k, n, mBytes);
        }
    }

    private void EncryptFullBlocks(ReadOnlySpan<byte> x, Span<byte> y, ReadOnlySpan<byte> k, int count)
    {
        for (int i = 0; i < count; i++)
            _block.Encrypt(x.Slice(i * 16, 16), k, y.Slice(i * 16, 16));
    }

    private void DecryptFullBlocks(ReadOnlySpan<byte> y, Span<byte> x, ReadOnlySpan<byte> k, int count)
    {
        for (int i = 0; i < count; i++)
            _block.Decrypt(y.Slice(i * 16, 16), k, x.Slice(i * 16, 16));
    }

    private void FinalizeEncryption(ReadOnlySpan<byte> x, Span<byte> y, ReadOnlySpan<byte> k, int n, int mBytes)
    {
        int idxPrev = (n - 2) * 16;
        int idxLast = (n - 1) * 16;

        Span<byte> ynFull = stackalloc byte[16];
        Span<byte> xnWithR = stackalloc byte[16];
        Span<byte> ynMinus1 = stackalloc byte[16];

        try
        {
            // 1) (Yn || r) = block(Xn-1, K)
            _block.Encrypt(x.Slice(idxPrev, 16), k, ynFull);

            // 2) Yn-1 = block(Xn || r, K)
            x.Slice(idxLast, mBytes).CopyTo(xnWithR);
            ynFull[mBytes..].CopyTo(xnWithR[mBytes..]); // копируем r
            _block.Encrypt(xnWithR, k, ynMinus1);

            // Безопасная запись (защита от in-place)
            ynFull[..mBytes].CopyTo(y.Slice(idxLast, mBytes));
            ynMinus1.CopyTo(y.Slice(idxPrev, 16));
        }
        finally
        {
            ynFull.Clear(); xnWithR.Clear(); ynMinus1.Clear();
        }
    }

    private void FinalizeDecryption(ReadOnlySpan<byte> y, Span<byte> x, ReadOnlySpan<byte> k, int n, int mBytes)
    {
        int idxPrev = (n - 2) * 16;
        int idxLast = (n - 1) * 16;

        Span<byte> xnFull = stackalloc byte[16];
        Span<byte> ynWithR = stackalloc byte[16];
        Span<byte> xnMinus1 = stackalloc byte[16];

        try
        {
            // 1) (Xn || r) = block^-1(Yn-1, K)
            _block.Decrypt(y.Slice(idxPrev, 16), k, xnFull);

            // 2) Xn-1 = block^-1(Yn || r, K)
            y.Slice(idxLast, mBytes).CopyTo(ynWithR);
            xnFull[mBytes..].CopyTo(ynWithR[mBytes..]); // копируем r
            _block.Decrypt(ynWithR, k, xnMinus1);

            // Безопасная запись
            xnFull[..mBytes].CopyTo(x.Slice(idxLast, mBytes));
            xnMinus1.CopyTo(x.Slice(idxPrev, 16));
        }
        finally
        {
            xnFull.Clear(); ynWithR.Clear(); xnMinus1.Clear();
        }
    }
}
