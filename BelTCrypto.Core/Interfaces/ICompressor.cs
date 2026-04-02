namespace BelTCrypto.Core.Interfaces;

public interface ICompressor
{
    /// <summary>
    /// Алгоритм сжатия belt-compress согласно СТБ 34.101.31 (6.3).
    /// </summary>
    /// <param name="x">Входное слово (512 бит / 64 байта).</param>
    /// <param name="s">Промежуточный результат (128 бит / 16 байт).</param>
    /// <param name="y">Окончательный результат (256 бит / 32 байта).</param>
    void Compress(ReadOnlySpan<byte> x, Span<byte> s, Span<byte> y) => throw new NotImplementedException();
}
