using BelTCrypto.Core.Interfaces;
using System.Buffers.Binary;

namespace BelTCrypto.Core;

internal class BelTKeyService : IBelTKeyService
{
    private readonly IBelTCompress _compressor;

    public BelTKeyService(IBelTCompress compressor)
    {
        _compressor = compressor ?? throw new ArgumentNullException(nameof(compressor));
    }

    public void Expand(ReadOnlySpan<byte> sourceKey, Span<byte> expandedKey)
    {
        // 8.1.1 Интерфейс: n — количество 32-битных фрагментов (4, 6 или 8)
        int n = sourceKey.Length / 4;

        if (n != 4 && n != 6 && n != 8)
            throw new ArgumentException("n должно быть равно 4, 6 или 8 (16, 24 или 32 байта).");

        if (expandedKey.Length < 32)
            throw new ArgumentException("Выходной буфер должен быть не менее 32 байт.");

        if (n == 4)
        {
            BelTMath.Word.Expand(sourceKey, expandedKey);
        }
        else if (n == 6)
        {
            BelTMath.Block.Expand(sourceKey, expandedKey);
        }
        // 3 Установить K ← K1 ‖ K2 ‖... ‖ K8. (Для случая n=8)
        else if (n == 8)
        {
            sourceKey.CopyTo(expandedKey);
        }

        // 4 Возвратить K.
    }



    /// <summary>
    /// 8.2.3 Алгоритм преобразования ключа (belt-keyrep)
    /// </summary>
    /// <param name="x">Исходный ключ X (128, 192 или 256 бит)</param>
    /// <param name="d">Уровень ключа D (96 бит / 12 байт)</param>
    /// <param name="i">Заголовок I (128 бит / 16 байт)</param>
    /// <param name="mBits">Целевая длина ключа m (128, 192, 256)</param>
    /// <param name="y">Выходной преобразованный ключ Y длиной mBits/8</param>
    public void Rep(ReadOnlySpan<byte> x, ReadOnlySpan<byte> d, ReadOnlySpan<byte> i, int mBits, Span<byte> y)
    {
        int nBits = x.Length * 8;

        // 1) Присвоить переменной r значение
        uint r = GetRConstant(nBits, mBits);

        // 2) s ← belt-keyexpand(X)
        Span<byte> sExpand = stackalloc byte[32];
        Expand(x, sExpand);

        // Подготовка входа для belt-compress (512 бит / 64 байта)
        Span<byte> compressInput = stackalloc byte[64];

        // r ‖ D (4 + 12 = 16 байт)
        BinaryPrimitives.WriteUInt32LittleEndian(compressInput[..4], r);
        d.CopyTo(compressInput.Slice(4, 12));

        // I (16 байт)
        i.CopyTo(compressInput.Slice(16, 16));

        // s (32 байта)
        sExpand.CopyTo(compressInput.Slice(32, 32));

        // 3) Установить (⊥,s) ← belt-compress(r ‖ D ‖ I ‖ s)
        Span<byte> sCompress = stackalloc byte[32]; // Результат Y компрессора (256 бит)
        Span<byte> dummyS = stackalloc byte[16];   // Промежуточный результат S (игнорируется)

        _compressor.Compress(compressInput, dummyS, sCompress);

        // 4) Установить Y ← Lo(s, m)
        int mBytes = mBits / 8;
        sCompress[..mBytes].CopyTo(y);

        // 5) Возвратить Y
    }

    private static uint GetRConstant(int n, int m)
    {
        return n switch
        {
            128 => BinaryPrimitives.ReadUInt32LittleEndian(BelTMath.R24.AsSpan()[..4]),
            192 when m == 128 => BinaryPrimitives.ReadUInt32LittleEndian(BelTMath.R24.AsSpan()[4..8]),
            192 when m == 192 => BinaryPrimitives.ReadUInt32LittleEndian(BelTMath.R24.AsSpan()[8..12]),
            256 when m == 128 => BinaryPrimitives.ReadUInt32LittleEndian(BelTMath.R24.AsSpan()[12..16]),
            256 when m == 192 => BinaryPrimitives.ReadUInt32LittleEndian(BelTMath.R24.AsSpan()[16..20]),
            256 when m == 256 => BinaryPrimitives.ReadUInt32LittleEndian(BelTMath.R24.AsSpan()[20..24]),
            _ => throw new ArgumentException($"Недопустимая комбинация длин ключей n={n}, m={m}")
        };
    }
}
