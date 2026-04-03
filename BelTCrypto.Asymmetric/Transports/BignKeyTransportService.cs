using BelTCrypto.Bign.Models;

namespace BelTCrypto.Bign.Transports;

public class BignKeyTransportService
{
    private readonly BignCurveParameters _params;
    private readonly EllipticCurve _curve;
    private const int HeaderSize = 16; // 128 бит

    public BignKeyTransportService(BignCurveParameters parameters)
    {
        _params = parameters;
        _curve = new EllipticCurve(parameters.A, parameters.B, parameters.P, parameters.Q, parameters.G);
    }

    /// <summary>
    /// Создание токена ключа (п. 7.2.1)
    /// </summary>
    /// <param name="keyToWrap">Секретный ключ, который мы передаем</param>
    /// <param name="recipientPubKey">Открытый ключ получателя (Q)</param>
    /// <param name="header">Заголовок I (16 байт). Если null, используются нули.</param>
    public BignToken? CreateToken(byte[] keyToWrap, ECPoint recipientPubKey, byte[]? header = null)
    {
        // 1. Подготовка заголовка I
        Span<byte> i = stackalloc byte[HeaderSize];
        if (header != null)
        {
            if (header.Length != HeaderSize)
                throw new ArgumentException($"Заголовок должен быть ровно {HeaderSize} байт.");
            header.CopyTo(i);
        }
        else
        {
            i.Clear(); // По умолчанию I = 0^128
        }

        // Дальнейшая логика по разделу 7.2...
        // Здесь мы будем генерировать k, вычислять точку R = kG и секрет W = kQ
        // А затем использовать твой belt-keywrap
        return null; // Stub
    }
}