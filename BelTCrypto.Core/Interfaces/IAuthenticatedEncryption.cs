namespace BelTCrypto.Core.Interfaces;

/// <summary>
/// Интерфейс для алгоритмов аутентифицированного шифрования (AEAD) согласно 7.6.1
/// </summary>
public interface IAuthenticatedEncryption
{
    /// <summary>
    /// Установка защиты (Шифрование + MAC)
    /// </summary>
    /// <param name="x">Открытый текст (сообщение)</param>
    /// <param name="i">Ассоциированные данные (не шифруются)</param>
    /// <param name="key">Ключ 256 бит</param>
    /// <param name="s">Синхропосылка 128 бит</param>
    /// <param name="y">Буфер для зашифрованного сообщения (размер |x|)</param>
    /// <param name="t">Буфер для имитовставки (8 байт)</param>
    void Protect(ReadOnlySpan<byte> x, ReadOnlySpan<byte> i, ReadOnlySpan<byte> key, ReadOnlySpan<byte> s, Span<byte> y, Span<byte> t);

    /// <summary>
    /// Снятие защиты (Расшифрование + Проверка)
    /// </summary>
    /// <returns>True, если данные целостны и расшифрованы. False, если ошибка (отказ в обслуживании)</returns>
    bool Unprotect(ReadOnlySpan<byte> y, ReadOnlySpan<byte> i, ReadOnlySpan<byte> t, ReadOnlySpan<byte> key, ReadOnlySpan<byte> s, Span<byte> x);
}
