using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTCompressor : IBelTCompress
{
    private readonly IBelTBlock _block;

    public BelTCompressor(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }
    public void Compress(ReadOnlySpan<byte> x, Span<byte> s, Span<byte> y)
    {
        // Валидация входных данных
        if (x.Length != 64) throw new ArgumentException("X должен быть 512 бит.");
        if (s.Length != 16) throw new ArgumentException("S должен быть 128 бит.");
        if (y.Length != 32) throw new ArgumentException("Y должен быть 256 бит.");

        // 1) Split(X, 128)
        ReadOnlySpan<byte> x1 = x[..16];
        ReadOnlySpan<byte> x2 = x.Slice(16, 16);
        ReadOnlySpan<byte> x3 = x.Slice(32, 16);
        ReadOnlySpan<byte> x4 = x.Slice(48, 16);

        Span<byte> k = stackalloc byte[32];
        Span<byte> beltOut = stackalloc byte[16];
        Span<byte> temp = stackalloc byte[16];

        // 2) S ← belt-block(X3 ⊕ X4, X1 ‖ X2) ⊕ X3 ⊕ X4
        x3.CopyTo(temp);
        BelTMath.GfBlock.Xor(temp, x4); // temp = X3 ⊕ X4

        x1.CopyTo(k.Slice(0, 16));
        x2.CopyTo(k.Slice(16, 16));

        _block.Encrypt(temp, k, beltOut);
        beltOut.CopyTo(s);
        BelTMath.GfBlock.Xor(s, temp); // Финальный S

        // 3) Y1 ← belt-block(X1, S ‖ X4) ⊕ X1
        s.CopyTo(k.Slice(0, 16));
        x4.CopyTo(k.Slice(16, 16));

        _block.Encrypt(x1, k, beltOut);
        Span<byte> y1 = y.Slice(0, 16);
        beltOut.CopyTo(y1);
        BelTMath.GfBlock.Xor(y1, x1);

        // 4) Y2 ← belt-block(X2, (S ⊕ 1^128) ‖ X3) ⊕ X2
        for (int j = 0; j < 16; j++) temp[j] = (byte)(s[j] ^ 0xFF); // Инверсия S

        temp.CopyTo(k.Slice(0, 16));
        x3.CopyTo(k.Slice(16, 16));

        _block.Encrypt(x2, k, beltOut);
        Span<byte> y2 = y.Slice(16, 16);
        beltOut.CopyTo(y2);
        BelTMath.GfBlock.Xor(y2, x2);
    }
}
