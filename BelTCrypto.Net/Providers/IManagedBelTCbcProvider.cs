using BelTCrypto.Net.Interfaces;

namespace BelTCrypto.Net.Providers;


public interface IManagedBelTCbcProvider
{
    /// <summary>
    /// Шифрование в режиме belt-cbc.
    /// </summary>
    /// <param name="data">Открытые данные.</param>
    /// <param name="iv">Синхропосылка (Вектор инициализации) строго 16 байт.</param>
    /// <param name="key">Управляемый криптографический ключ.</param>
    /// <param name="output">Буфер для шифротекста.</param>
    void Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output);

    /// <summary>
    /// Расшифрование в режиме belt-cbc.
    /// </summary>
    void Decrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output);
}
