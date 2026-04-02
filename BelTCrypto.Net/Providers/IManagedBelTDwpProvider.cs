using BelTCrypto.Net.Interfaces;

namespace BelTCrypto.Net.Providers;

public interface IManagedBelTDwpProvider
{
    /// <summary>
    /// Аутентифицированное шифрование (belt-dwp).
    /// </summary>
    /// <param name="data">Данные для шифрования.</param>
    /// <param name="ad">Связанные данные (передаются открыто, но защищены имитовставкой).</param>
    /// <param name="iv">Синхропосылка (16 байт).</param>
    /// <param name="key">Управляемый ключ.</param>
    /// <param name="output">Буфер для шифротекста (size == data.Length).</param>
    /// <param name="tag">Буфер для имитовставки (8 байт).</param>
    void Protect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output, Span<byte> tag);

    /// <summary>
    /// Расшифрование и проверка целостности (belt-dwp).
    /// </summary>
    /// <returns>True, если данные подлинны и успешно расшифрованы.</returns>
    bool Unprotect(ReadOnlySpan<byte> data, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output, ReadOnlySpan<byte> expectedTag);
}
