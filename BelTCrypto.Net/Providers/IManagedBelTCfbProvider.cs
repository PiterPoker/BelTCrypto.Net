using BelTCrypto.Net.Interfaces;

namespace BelTCrypto.Net.Providers;

public interface IManagedBelTCfbProvider
{
    /// <summary>
    /// Шифрование в режиме обратной связи по шифротексту (belt-cfb).
    /// Поддерживает данные любой длины (потоковый режим).
    /// </summary>
    void Encrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output);

    /// <summary>
    /// Расшифрование в режиме обратной связи по шифротексту (belt-cfb).
    /// </summary>
    void Decrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output);
}
