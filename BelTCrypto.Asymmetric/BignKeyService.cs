using BelTCrypto.Bign.Models;
using System.Numerics;
using System.Security.Cryptography;

namespace BelTCrypto.Bign;

public class BignKeyService
{
    private readonly BignCurveParameters _params;
    private readonly EllipticCurve _curve;

    public BignKeyService(BignCurveParameters parameters)
    {
        _params = parameters;
        _curve = new EllipticCurve(parameters.A, parameters.B, parameters.P, parameters.Q, parameters.G);
    }

    /// <summary>
    /// Генерация пары ключей (п. 6.2.2)
    /// </summary>
    public BignKeyPair GenerateKeyPair()
    {
        // 1. Генерация личного ключа d
        BigInteger d = GenerateRandomExponent();

        // 2. Вычисление открытого ключа Q = dG
        Models.ECPoint q = _curve.Multiply(_params.G, d);

        return new BignKeyPair(d, q);
    }

    /// <summary>
    /// Генерация числа в диапазоне [1, q-1] методом из Примечания к 5.4
    /// </summary>
    public BigInteger GenerateRandomExponent()
    {
        int byteLength = _params.L / 4; // 2l бит = l/4 байт (напр. 32 байта для l=128)
        byte[] buffer = new byte[byteLength];

        while (true)
        {
            RandomNumberGenerator.Fill(buffer);

            // Превращаем в положительное число (Little-Endian согласно СТБ)
            BigInteger candidate = new BigInteger(buffer, isUnsigned: true, isBigEndian: false);

            // Условие: d ∈ {1, 2, ..., q-1}
            if (candidate >= 1 && candidate < _params.Q)
            {
                return candidate;
            }
        }
    }

    public byte[] SerializePublicKey(Models.ECPoint q)
    {
        int coordSize = _params.L / 4; // 2l бит
        byte[] result = new byte[coordSize * 2]; // 4l бит

        // Пишем x, затем y (Little-Endian)
        if (!q.X.TryWriteBytes(result.AsSpan(0, coordSize), out _, isUnsigned: true, isBigEndian: false) ||
            !q.Y.TryWriteBytes(result.AsSpan(coordSize, coordSize), out _, isUnsigned: true, isBigEndian: false))
        {
            throw new CryptographicException("Ошибка сериализации точки.");
        }

        return result;
    }
}