namespace BelTCrypto.Core.Interfaces;

public interface IBelTFmt
{
    /// <summary>
    /// Шифрование с сохранением формата (belt-fmt)
    /// </summary>
    /// <param name="x">Входное слово в алфавите Zm</param>
    /// <param name="m">Размер алфавита (2..65536)</param>
    /// <param name="k">Ключ 256 бит</param>
    /// <param name="s">Синхропосылка 128 бит</param>
    /// <param name="y">Выходное зашифрованное слово</param>
    void Encrypt(ReadOnlySpan<ushort> x, int m, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<ushort> y);

    void Decrypt(ReadOnlySpan<ushort> y, int m, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<ushort> x);
}