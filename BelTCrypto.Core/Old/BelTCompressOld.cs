using BelTCrypto.Core.Interfaces.Old;

namespace BelTCrypto.Core.Old;

[Obsolete]
internal sealed class BelTCompressOld(IBelTBlockOld block) : IBelTCompressOld
{
    private readonly IBelTBlockOld _block = block ?? throw new ArgumentNullException(nameof(block));
    private bool _disposed;
    public (byte[] S, byte[] Y) Compress(ReadOnlySpan<byte> x)
    {
        if (x.Length != 64) // 512 бит = 64 байта
            throw new ArgumentException("Input X must be 512 bits (64 bytes).");

        // 1. (X1, X2, X3, X4) = Split(X, 128)
        byte[] x1 = x[..16].ToArray();
        byte[] x2 = x.Slice(16, 16).ToArray();
        byte[] x3 = x.Slice(32, 16).ToArray();
        byte[] x4 = x.Slice(48, 16).ToArray();

        // Подготовка буферов
        byte[] s = new byte[16];
        byte[] y1 = new byte[16];
        byte[] y2 = new byte[16];
        byte[] tempKey = new byte[32];
        byte[] x3XorX4 = new byte[16];

        // 2. S = belt-block(X3 ^ X4, X1 || X2) ^ X3 ^ X4
        for (int i = 0; i < 16; i++) x3XorX4[i] = (byte)(x3[i] ^ x4[i]);

        // Ключ K = X1 || X2
        x1.CopyTo(tempKey, 0);
        x2.CopyTo(tempKey, 16);

        _block.ResetKey(tempKey);
        _block.Encrypt(x3XorX4, s);
        for (int i = 0; i < 16; i++) s[i] ^= x3XorX4[i];

        // 3. Y1 = belt-block(X1, S || X4) ^ X1
        // Ключ K = S || X4
        s.CopyTo(tempKey, 0);
        x4.CopyTo(tempKey, 16);

        _block.ResetKey(tempKey);
        _block.Encrypt(x1, y1);
        for (int i = 0; i < 16; i++) y1[i] ^= x1[i];

        // 4. Y2 = belt-block(X2, (S ^ 1^128) || X3) ^ X2
        // S ^ 1^128 — это побитовое отрицание NOT
        byte[] sNot = new byte[16];
        for (int i = 0; i < 16; i++) sNot[i] = (byte)(s[i] ^ 0xFF);

        // Ключ K = (S ^ 1^128) || X3
        sNot.CopyTo(tempKey, 0);
        x3.CopyTo(tempKey, 16);

        _block.ResetKey(tempKey);
        _block.Encrypt(x2, y2);
        for (int i = 0; i < 16; i++) y2[i] ^= x2[i];

        // Сборка Y = Y1 || Y2
        byte[] y = new byte[32];
        y1.CopyTo(y, 0);
        y2.CopyTo(y, 16);

        return (s, y);
    }


    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            _block?.Dispose();
        }

        _disposed = true;
    }
}