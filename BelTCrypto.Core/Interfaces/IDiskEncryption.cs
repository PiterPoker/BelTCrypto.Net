namespace BelTCrypto.Core.Interfaces;

public interface IDiskEncryption
{
    /// <summary>
    /// Зашифрование данных (belt-bde или belt-sde)
    /// </summary>
    /// <param name="x">Исходные данные (содержимое сектора)</param>
    /// <param name="k">Ключ (256 бит)</param>
    /// <param name="s">Синхропосылка (128 бит, обычно номер сектора)</param>
    /// <param name="y">Буфер для зашифрованных данных</param>
    void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y);

    /// <summary>
    /// Расшифрование данных (belt-bde-1 или belt-sde-1)
    /// </summary>
    /// <param name="y">Зашифрованные данные</param>
    /// <param name="k">Ключ (256 бит)</param>
    /// <param name="s">Синхропосылка (128 бит)</param>
    /// <param name="x">Буфер для расшифрованных данных</param>
    void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x);
}