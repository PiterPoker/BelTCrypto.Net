using BelTCrypto.Core;
using BelTCrypto.Core.Interfaces.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public sealed class BelTMac : KeyedHashAlgorithm
{
    private readonly IBelTMacOld _engine;
    private readonly byte[] _buffer = new byte[16];
    private int _bufferOffset;

    public BelTMac(byte[] key)
    {
        // Используем твою фабрику из Core
        var block = BeltHash.BelTBlock(key);
        _engine = BeltHash.BelTMac(block);
        HashSizeValue = 64;
    }

    public override void Initialize()
    {
        _engine.Reset();
        _bufferOffset = 0;
        Array.Clear(_buffer, 0, _buffer.Length);
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        int processed = 0;
        while (processed < cbSize)
        {
            // Если буфер уже полный, а данные еще идут — 
            // значит этот блок из буфера ТОЧНО не последний. Процессим его.
            if (_bufferOffset == 16)
            {
                _engine.ProcessBlock(_buffer);
                _bufferOffset = 0;
            }

            int remainingInArray = cbSize - processed;
            int spaceInBuffer = 16 - _bufferOffset;
            int toCopy = Math.Min(remainingInArray, spaceInBuffer);

            Array.Copy(array, ibStart + processed, _buffer, _bufferOffset, toCopy);

            _bufferOffset += toCopy;
            processed += toCopy;
        }
    }

    protected override byte[] HashFinal()
    {
        // Вся магия выбора Phi1/Phi2 теперь инкапсулирована в Core.
        // Мы просто отдаем то, что осталось в буфере (от 0 до 16 байт).
        return _engine.Finalize(_buffer.AsSpan(0, _bufferOffset), _bufferOffset);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _engine?.Dispose();
            CryptographicOperations.ZeroMemory(_buffer);
        }
        base.Dispose(disposing);
    }
}