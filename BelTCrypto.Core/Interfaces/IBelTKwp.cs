namespace BelTCrypto.Core.Interfaces;

public interface IBelTKwp
{
    /// <summary>
    /// Установка защиты ключа (belt-kwp)
    /// </summary>
    /// <param name="x">Защищаемый ключ (длина >= 16 байт)</param>
    /// <param name="i">Заголовок (ровно 16 байт)</param>
    /// <param name="k">Ключ защиты (32 байта)</param>
    /// <param name="y">Выходной защищенный ключ (длина x.Length + 16)</param>
    void Protect(ReadOnlySpan<byte> x, ReadOnlySpan<byte> i, ReadOnlySpan<byte> k, Span<byte> y);

    /// <summary>
    /// Снятие защиты ключа (belt-kwp-1)
    /// </summary>
    /// <param name="y">Защищенный ключ</param>
    /// <param name="i">Ожидаемый заголовок (16 байт)</param>
    /// <param name="k">Ключ защиты (32 байта)</param>
    /// <param name="x">Выходной исходный ключ (длина y.Length - 16)</param>
    /// <returns>True, если целостность подтверждена; иначе False (⊥)</returns>
    bool Unprotect(ReadOnlySpan<byte> y, ReadOnlySpan<byte> i, ReadOnlySpan<byte> k, Span<byte> x);
}