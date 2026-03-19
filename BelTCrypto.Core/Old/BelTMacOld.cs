using BelTCrypto.Core.Interfaces.Old;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Old;

internal class BelTMacOld : IBelTMacOld
{
    private readonly IBelTBlockOld _block;
    private readonly byte[] _r = new byte[16];
    private readonly byte[] _s = new byte[16];
    private bool _isDisposed;

    public BelTMacOld(IBelTBlockOld block)
    {
        _block = block;
        // Шаг 2: r = belt-block(0^128, K)
        byte[] zeros = new byte[16];
        _block.Encrypt(zeros, _r);
    }

    public void Reset()
    {
        Array.Clear(_s, 0, 16);
    }

    public void ProcessBlock(ReadOnlySpan<byte> block)
    {
        // Шаг 3: s = belt-block(s ^ Xi, K)
        for (int i = 0; i < 16; i++) _s[i] ^= block[i];
        _block.Encrypt(_s, _s);
    }
    public byte[] Finalize(ReadOnlySpan<byte> lastChunk, int length)
    {
        byte[] phiRes = new byte[16];
        byte[] xn = new byte[16];

        if (length == 16)
        {
            BelTMathOld.ApplyPhi1(_r, phiRes);
            lastChunk.CopyTo(xn);
        }
        else
        {
            BelTMathOld.ApplyPhi2(_r, phiRes);
            BelTMathOld.ApplyPsi(lastChunk[..length], xn);
        }

        // Создаем ЛОКАЛЬНЫЙ массив для входа в последнее шифрование
        byte[] finalInput = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            // XOR-им текущее состояние s (из поля класса) с xn и phiRes
            finalInput[i] = (byte)(_s[i] ^ xn[i] ^ phiRes[i]);
        }

        byte[] finalBlock = new byte[16];
        // Шифруем локальный буфер, а не _s!
        _block.Encrypt(finalInput, finalBlock);

        byte[] t = new byte[8];
        Array.Copy(finalBlock, 0, t, 0, 8);
        return t;
    }

    public void Dispose()
    {
        if (_isDisposed) return;
        CryptographicOperations.ZeroMemory(_s);
        CryptographicOperations.ZeroMemory(_r);
        _block?.Dispose();
        _isDisposed = true;
    }
}