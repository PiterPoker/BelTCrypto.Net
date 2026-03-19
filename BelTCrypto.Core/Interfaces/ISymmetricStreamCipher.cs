namespace BelTCrypto.Core.Interfaces;

/// <summary>
/// Интерфейс для симметричных режимов, где зашифрование и расшифрование идентичны
/// </summary>
public interface ISymmetricStreamCipher
{
    /// <summary>
    /// Преобразование данных (зашифрование или расшифрование)
    /// </summary>
    /// <param name="data">Входной буфер (X или Y)</param>
    /// <param name="k">Ключ 256 бит</param>
    /// <param name="s">Синхропосылка 128 бит</param>
    /// <param name="result">Выходной буфер той же длины</param>
    void Process(ReadOnlySpan<byte> data, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> result);
}
