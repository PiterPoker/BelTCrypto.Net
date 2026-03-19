using BelTCrypto.Core.Interfaces;
using System.Buffers.Binary;

namespace BelTCrypto.Core;

internal class BelTWideBlock : IBelTWideBlock
{
    private IBelTBlock _block;

    public BelTWideBlock(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }
    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, Span<byte> y)
    {
        if (x.Length < 32) throw new ArgumentException("Длина X должна быть не менее 32 байт.");

        // Шаг 1: r ← X
        x.CopyTo(y);
        int nBytes = y.Length;
        int n = (nBytes + 15) / 16;

        Span<byte> s = stackalloc byte[16];
        Span<byte> beltOut = stackalloc byte[16];
        Span<byte> iBlock = stackalloc byte[16];

        try
        {
            // Шаг 3: Основной цикл i = 1, 2, ..., 2n
            for (int i = 1; i <= 2 * n; i++)
            {
                ExecuteEncryptStep(k, y, nBytes, n, s, beltOut, iBlock, i);
            }
        }
        finally
        {
            s.Clear();
            beltOut.Clear();
            iBlock.Clear();
        }
    }

    private void ExecuteEncryptStep(ReadOnlySpan<byte> k, Span<byte> y, int nBytes, int n, Span<byte> s, Span<byte> beltOut, Span<byte> iBlock, int i)
    {

        // 3.1) s ← r1 ⊕ r2 ⊕ ... ⊕ rn-1
        s.Clear();
        for (int j = 0; j < n - 1; j++)
        {
            BelTMath.GfBlock.Xor(s, y.Slice(j * 16, 16));
        }

        // 3.2) r* ← r* ⊕ belt-block(s, K) ⊕ ⟨i⟩128
        _block.Encrypt(s, k, beltOut);

        iBlock.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(iBlock, (uint)i);

        Span<byte> rStar = y.Slice(nBytes - 16, 16);
        BelTMath.GfBlock.Xor(rStar, beltOut);
        BelTMath.GfBlock.Xor(rStar, iBlock);

        // 3.3) r ← ShLo128(r) -> Циклический сдвиг всего блока влево на 128 бит
        Span<byte> rTemp = stackalloc byte[nBytes];
        BelTMath.Block.RotHi(y, rTemp, 128);
        rTemp.CopyTo(y);

        // 3.4) r* ← s
        s.CopyTo(y.Slice(nBytes - 16, 16));
    }

    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, Span<byte> x)
    {
        if (y.Length < 32) throw new ArgumentException("Длина Y должна быть не менее 32 байт.");
        if (x.Length != y.Length) throw new ArgumentException("Размер выходного буфера должен совпадать с входным.");

        // Шаг 1: r ← Y
        y.CopyTo(x);
        int nBytes = x.Length;
        int n = (nBytes + 15) / 16;

        Span<byte> s = stackalloc byte[16];
        Span<byte> beltOut = stackalloc byte[16];
        Span<byte> iBlock = stackalloc byte[16];

        try
        {
            // Шаг 3: Цикл i = 2n, 2n-1, ..., 1
            for (int i = 2 * n; i >= 1; i--)
            {
                ExecuteDecryptStep(k, x, nBytes, n, s, beltOut, iBlock, i);
            }
        }
        finally
        {
            s.Clear();
            beltOut.Clear();
            iBlock.Clear();
        }
    }

    private void ExecuteDecryptStep(ReadOnlySpan<byte> k, Span<byte> r, int nBytes, int n, Span<byte> s, Span<byte> beltOut, Span<byte> iBlock, int i)
    {
        // 3.1) s ← r*
        r.Slice(nBytes - 16, 16).CopyTo(s);

        // 3.2) r ← ShHi128(r)
        // Циклический сдвиг вправо на 16 байт (128 бит) через твой RotHi
        Span<byte> rTemp = stackalloc byte[nBytes];
        BelTMath.Block.RotHi(r, rTemp, (nBytes - 16) * 8);
        rTemp.CopyTo(r);

        // 3.3) r* ← r* ⊕ belt-block(s, K) ⊕ ⟨i⟩128
        _block.Encrypt(s, k, beltOut);
        BinaryPrimitives.WriteUInt32LittleEndian(iBlock, (uint)i);

        Span<byte> rStar = r.Slice(nBytes - 16, 16);
        BelTMath.GfBlock.Xor(rStar, beltOut);
        BelTMath.GfBlock.Xor(rStar, iBlock);

        // 3.4) r1 ← s ⊕ r2 ⊕ ... ⊕ rn-1
        Span<byte> r1 = r[..16];
        s.CopyTo(r1);
        for (int j = 1; j < n - 1; j++)
        {
            BelTMath.GfBlock.Xor(r1, r.Slice(j * 16, 16));
        }
    }
}
