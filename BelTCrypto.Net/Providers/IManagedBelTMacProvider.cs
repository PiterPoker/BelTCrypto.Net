using BelTCrypto.Net.Interfaces;

namespace BelTCrypto.Net.Providers;

public interface IManagedBelTMacProvider
{
    /// <summary>
    /// Вычисление имитовставки (belt-mac).
    /// </summary>
    /// <param name="data">Данные любой длины.</param>
    /// <param name="key">Управляемый ключ.</param>
    /// <param name="mac">Буфер для результата (ровно 8 байт).</param>
    void Compute(ReadOnlySpan<byte> data, ISecureCryptoKey key, Span<byte> mac);

    /// <summary>
    /// Проверка имитовставки.
    /// </summary>
    /// <returns>True, если MAC верный.</returns>
    bool Verify(ReadOnlySpan<byte> data, ISecureCryptoKey key, ReadOnlySpan<byte> expectedMac);
}