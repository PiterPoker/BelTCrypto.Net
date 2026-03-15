using BelTCrypto.Core;
using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public sealed class BeltAead : IDisposable
{
    private readonly IBelTAead _engine;
    private readonly int _tagSize = 8; // T ∈ {0,1}64 по стандарту

    public BeltAead(byte[] key, BeltAeadScheme scheme = BeltAeadScheme.Dwp)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32) throw new ArgumentException("Ключ BelT должен быть 256 бит (32 байта).");

        // Инициализируем Core-движок через нашу фабрику
        var block = BeltHash.BelTBlock(key); // Твой класс реализации блочного шифра

        _engine = scheme switch
        {
            BeltAeadScheme.Dwp => BeltHash.BelTDwp(block),
            // BelTChe добавим позже
            _ => throw new NotSupportedException($"Схема {scheme} еще не реализована.")
        };
    }

    /// <summary>
    /// Аутентифицированное шифрование
    /// </summary>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData = default)
    {
        CheckArguments(nonce, plaintext, ciphertext, tag);

        var (ct, t) = _engine.Protect(plaintext, associatedData, nonce);

        ct.CopyTo(ciphertext);
        t.CopyTo(tag);
    }

    /// <summary>
    /// Аутентифицированное расшифрование
    /// </summary>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData = default)
    {
        CheckArguments(nonce, plaintext, ciphertext, tag);

        try
        {
            byte[] result = _engine.Unprotect(ciphertext, associatedData, nonce, tag);
            result.CopyTo(plaintext);
        }
        catch (Exception ex)
        {
            // В криптографии важно затирать результат при ошибке
            plaintext.Clear();
            throw new CryptographicException("Ошибка аутентификации: данные повреждены или ключ неверен.", ex);
        }
    }

    private void CheckArguments(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> p1, ReadOnlySpan<byte> p2, ReadOnlySpan<byte> tag)
    {
        if (nonce.Length != 16) throw new ArgumentException("IV (nonce) должен быть 16 байт.");
        if (tag.Length != _tagSize) throw new ArgumentException($"Тег должен быть {_tagSize} байт.");
        if (p1.Length != p2.Length) throw new ArgumentException("Длина входных и выходных данных должна совпадать.");
    }

    public void Dispose() => _engine.Dispose();
}