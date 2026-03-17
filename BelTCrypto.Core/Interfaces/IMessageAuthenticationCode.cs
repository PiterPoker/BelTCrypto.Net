namespace BelTCrypto.Core.Interfaces;

/// <summary>
/// Универсальный интерфейс для алгоритмов выработки имитовставки (MAC)
/// </summary>
public interface IMessageAuthenticationCode
{
    /// <summary>
    /// Вычисляет имитовставку для сообщения
    /// </summary>
    /// <param name="data">Входное сообщение X произвольной длины</param>
    /// <param name="key">Ключ K (для belt-mac — 256 бит)</param>
    /// <param name="mac">Выходной буфер для имитовставки T (для belt-mac — 8 байт)</param>
    void Compute(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Span<byte> mac);

    /// <summary>
    /// Проверяет соответствие имитовставки сообщению
    /// </summary>
    /// <param name="data">Сообщение</param>
    /// <param name="key">Ключ</param>
    /// <param name="expectedMac">Имитовставка для проверки</param>
    /// <returns>True, если имитовставка верна</returns>
    bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> expectedMac);
}