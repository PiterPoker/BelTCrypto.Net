using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

/// <summary>
/// Реализация алгоритмов секторного зашифрования (belt-sde) 
/// и расшифрования (belt-sde^-1) согласно СТБ 34.101.31-2020.
/// </summary>
internal sealed class BelTSde : IBelTSde
{
    private readonly IBelTBlock _block;
    private readonly IBelTWideBlock _wideBlock;
    private const int BlockSize = 16;

    public BelTSde(IBelTBlock block, IBelTWideBlock wideBlock)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
        _wideBlock = wideBlock ?? throw new ArgumentNullException(nameof(wideBlock));
    }

    /// <summary>
    /// Зашифрование данных сектора (п. 7.9.5).
    /// </summary>
    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y)
    {
        if (x.Length < 32 || x.Length % BlockSize != 0)
            throw new ArgumentException("Длина сектора должна быть кратна 128 битам и не менее 256 бит.");

        // 1. Установить Y ← X
        x.CopyTo(y);

        // 3. Установить s_mask ← belt-block(S, K)
        Span<byte> derivedS = stackalloc byte[BlockSize];
        _block.Encrypt(s, k, derivedS);

        try
        {
            // 2 & 4. Установить Y1 ← Y1 ⊕ s_mask
            Span<byte> y1 = y.Slice(0, BlockSize);
            BelTMath.GfBlock.Xor(y1, derivedS);

            // 5. Установить Y ← belt-wblock(Y, K)
            _wideBlock.Encrypt(y, k, y);

            // 6. Установить Y1 ← Y1 ⊕ s_mask
            BelTMath.GfBlock.Xor(y1, derivedS);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedS);
        }
    }

    /// <summary>
    /// Расшифрование данных сектора (п. 7.9.6).
    /// </summary>
    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x)
    {
        if (y.Length < 32 || y.Length % BlockSize != 0)
            throw new ArgumentException("Длина сектора должна быть кратна 128 битам и не менее 256 бит.");

        // 1. Установить X ← Y
        y.CopyTo(x);

        // 3. Установить s_mask ← belt-block(S, K)
        Span<byte> derivedS = stackalloc byte[BlockSize];
        _block.Encrypt(s, k, derivedS);

        try
        {
            // 2 & 4. Установить X1 ← X1 ⊕ s_mask
            Span<byte> x1 = x.Slice(0, BlockSize);
            BelTMath.GfBlock.Xor(x1, derivedS);

            // 5. Установить X ← belt-wblock^-1(X, K)
            _wideBlock.Decrypt(x, k, x);

            // 6. Установить X1 ← X1 ⊕ s_mask
            BelTMath.GfBlock.Xor(x1, derivedS);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedS);
        }
    }
}