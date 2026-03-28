using BelTCrypto.Core.Interfaces;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace BelTCrypto.Core;

internal class BelTBde : IBelTBde
{
    private readonly IBelTBlock _block;
    private const int BlockSize = 16;

    public BelTBde(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }

    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x)
    {
        if (y.Length < BlockSize)
            throw new ArgumentException("Длина данных должна быть не меньше 128 бит.");
        if (y.Length % BlockSize != 0)
            throw new ArgumentException("Длина данных должна быть кратна 128 битам.");
        if (y.Length != x.Length)
            throw new ArgumentException("Размер входного и выходного буферов должен совпадать.");

        // Шаг 2: Установить s ← belt-block(S, K)
        Span<byte> currentS = stackalloc byte[BlockSize];
        _block.Encrypt(s, k, currentS);

        // Шаг 1: Split(Y, 128)
        int n = y.Length / BlockSize;

        // Шаг 3: Цикл по i=1..n
        for (int i = 0; i < n; i++)
        {
            // 3.1) s ← s * C
            BelTMath.GfBlock.Multiply(currentS, BelTMath.C);

            int offset = i * BlockSize;

            // 3.2) Xi ← belt-block-1(Yi ⊕ s, K) ⊕ s
            DecryptBlock(y.Slice(offset, BlockSize), k, currentS, x.Slice(offset, BlockSize));
        }

        // Шаг 4: Возвратить X (результат уже в x благодаря слайсам)
        CryptographicOperations.ZeroMemory(currentS);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void DecryptBlock(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> k,
        ReadOnlySpan<byte> s,
        Span<byte> output)
    {
        Span<byte> buffer = stackalloc byte[BlockSize];
        input.CopyTo(buffer);

        // Yi ⊕ s
        BelTMath.GfBlock.Xor(buffer, s);

        // belt-block-1(..., K)
        _block.Decrypt(buffer, k, output);

        // Результат ⊕ s
        BelTMath.GfBlock.Xor(output, s);
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y)
    {
        if (x.Length < BlockSize)
            throw new ArgumentException("Длина данных должна быть не меньше 128 бит.");
        if (x.Length % BlockSize != 0)
            throw new ArgumentException("Длина данных должна быть кратна 128 битам.");
        if (x.Length != y.Length)
            throw new ArgumentException("Размер входного и выходного буферов должен совпадать.");

        // Шаг 2: Установить s ← belt-block(S, K)
        Span<byte> currentS = stackalloc byte[BlockSize];
        _block.Encrypt(s, k, currentS);

        // Шаг 1: Split(X, 128)
        int n = x.Length / BlockSize;

        // Шаг 3: Цикл по i=1..n
        for (int i = 0; i < n; i++)
        {
            // 3.1) s ← s * C
            BelTMath.GfBlock.Multiply(currentS, BelTMath.C);

            int offset = i * BlockSize;
            EncryptBlock(x.Slice(offset, BlockSize),k,currentS,y.Slice(offset, BlockSize));
        }

        // Шаг 4: Возвратить Y (уже находится в буфере y благодаря слайсам)
        CryptographicOperations.ZeroMemory(currentS);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EncryptBlock(
    ReadOnlySpan<byte> input,
    ReadOnlySpan<byte> k,
    ReadOnlySpan<byte> s,
    Span<byte> output)
    {
        // Используем твой BelTMath.GfBlock.Xor
        Span<byte> buffer = stackalloc byte[BlockSize];
        input.CopyTo(buffer);
        BelTMath.GfBlock.Xor(buffer, s); // buffer = Xi ⊕ s

        _block.Encrypt(buffer, k, output);

        // Финальный XOR: Yi = Yi ⊕ s
        BelTMath.GfBlock.Xor(output, s);
    }
}
