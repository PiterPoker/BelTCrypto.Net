using BelTCrypto.Net.Interfaces;

namespace BelTCrypto.Net.Providers;

interface IManagedBelTCtrProvider
{
    /// <summary>
    /// Шифрование в режиме счетчика (belt-ctr).
    /// Идеально для распараллеливания и потоковой передачи данных.
    /// </summary>
    /// <param name="data">Открытые данные (любой длины).</param>
    /// <param name="iv">Синхропосылка (СТРОГО УНИКАЛЬНАЯ ДЛЯ КАЖДОГО ВЫЗОВА, 16 байт).</param>
    /// <param name="key">Управляемый криптографический ключ.</param>
    /// <param name="output">Буфер для шифротекста (должен быть >= data.Length).</param>
    void Process(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, ISecureCryptoKey key, Span<byte> output);
}
