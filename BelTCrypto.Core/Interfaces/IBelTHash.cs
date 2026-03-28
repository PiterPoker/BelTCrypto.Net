namespace BelTCrypto.Core.Interfaces;

/// <summary>
/// Интерфейс алгоритма хэширования belt-hash (СТБ 34.101.31)
/// </summary>
public interface IBelTHash
{
    /// <summary>
    /// Вычисляет хэш-значение Y для сообщения X.
    /// </summary>
    /// <param name="x">Входное сообщение X произвольной длины.</param>
    /// <param name="y">Выходной хэш Y (256 бит / 32 байта).</param>
    void ComputeHash(ReadOnlySpan<byte> x, Span<byte> y);
}