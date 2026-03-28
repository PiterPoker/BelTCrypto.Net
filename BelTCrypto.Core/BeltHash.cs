using System.Buffers.Binary;
using System.Security.Cryptography;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

/// <summary>
/// Реализация алгоритма хэширования belt-hash согласно СТБ 34.101.31-2020 (п. 7.8).
/// </summary>
internal sealed class BelTHash : IBelTHash
{
    private readonly IBelTCompress _compressor;
    private const int HashSize = 32;       // 256 бит
    private const int MessageBlockSize = 32; // 256 бит (п. 7.8.3, шаг 1)

    public BelTHash(IBelTCompress compressor)
    {
        _compressor = compressor ?? throw new ArgumentNullException(nameof(compressor));
    }

    public void ComputeHash(ReadOnlySpan<byte> x, Span<byte> y)
    {
        if (y.Length != HashSize)
            throw new ArgumentException($"Размер буфера Y должен быть {HashSize} байт (256 бит).", nameof(y));

        // --- 7.8.2 Переменные ---
        Span<byte> r = stackalloc byte[16]; // Длина сообщения (128 бит)
        Span<byte> s = stackalloc byte[16]; // Контрольная сумма (128 бит)
        Span<byte> t = stackalloc byte[16]; // Промежуточный результат t
        Span<byte> h = stackalloc byte[32]; // Текущее состояние хэша (256 бит)

        // Буферы для работы компрессора
        Span<byte> compressInput = stackalloc byte[64];
        Span<byte> currentBlock = compressInput[..32]; // Xi

        try
        {
            // --- 7.8.3 Шаг 2: Установить ---

            // 2.1) r ← ⟨|X|⟩_128 (Длина в битах)
            r.Clear();
            BinaryPrimitives.WriteUInt64LittleEndian(r, (ulong)x.Length * 8);

            // 2.2) s ← 0^128
            s.Clear();

            // 2.3) h ← IV (Константа из таблицы 2)
            BelTMath.H[..32].CopyTo(h);

            // --- 7.8.3 Шаг 1: Split(X, 256) ---
            int n = (x.Length + MessageBlockSize - 1) / MessageBlockSize;

            // --- 7.8.3 Шаг 3: Цикл (выполняется, если сообщение не пустое) ---
            for (int i = 0; i < n; i++)
            {
                int offset = i * MessageBlockSize;
                int remaining = x.Length - offset;
                int copyLen = Math.Min(remaining, MessageBlockSize);

                // 2.4) Xn ← Xn ‖ 0 (Дополнение нулями до 256 бит)
                currentBlock.Clear();
                x.Slice(offset, copyLen).CopyTo(currentBlock);

                // 3.1) (t, h) ← belt-compress(Xi ‖ h)
                // Xi уже в первых 32 байтах compressInput, копируем h во вторые 32 байта
                h.CopyTo(compressInput[32..]);

                _compressor.Compress(compressInput, t, h);

                // 3.2) s ← s ⊕ t
                BelTMath.GfBlock.Xor(s, t);
            }

            // --- 7.8.3 Шаг 4: Финализация ---
            // (⊥, Y) ← belt-compress(r ‖ s ‖ h)
            Span<byte> finalInput = stackalloc byte[64];
            r.CopyTo(finalInput[0..16]);
            s.CopyTo(finalInput[16..32]);
            h.CopyTo(finalInput[32..64]);

            // Результат записывается напрямую в выходной буфер y
            _compressor.Compress(finalInput, t, y);
        }
        finally
        {
            // Очистка КИЗИ (Конфиденциальной информации)
            CryptographicOperations.ZeroMemory(r);
            CryptographicOperations.ZeroMemory(s);
            CryptographicOperations.ZeroMemory(t);
            CryptographicOperations.ZeroMemory(h);
            CryptographicOperations.ZeroMemory(compressInput);
        }
    }
}