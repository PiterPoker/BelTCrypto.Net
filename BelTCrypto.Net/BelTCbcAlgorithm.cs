using BelTCrypto.Core;
using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public sealed class BelTCbcAlgorithm : SymmetricAlgorithm
{
    private readonly Func<byte[], IBelTBlock> _blockFactory;

    public BelTCbcAlgorithm(Func<byte[], IBelTBlock> blockFactory)
    {
        _blockFactory = blockFactory;

        // Настройки согласно СТБ 34.101.31
        KeySizes[] supportedKeys = [new(128, 256, 64)]; // 128, 192, 256 бит
        KeySizeValue = 256;
        BlockSizeValue = 128;
        FeedbackSizeValue = 128;
        LegalKeySizesValue = supportedKeys;
        LegalBlockSizesValue = [new KeySizes(128, 128, 0)];

        // Режим по умолчанию
        ModeValue = CipherMode.CBC;
        PaddingValue = PaddingMode.None; // Для CTS паддинг не нужен (он сам справляется)
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        if (rgbIV == null || rgbIV.Length != 16)
            throw new ArgumentException("IV must be 128 bits", nameof(rgbIV));

        var block = _blockFactory(rgbKey);
        return BeltHash.BelTCbcEncryptTransform(block, rgbIV);
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        if (rgbIV == null || rgbIV.Length != 16)
            throw new ArgumentException("IV must be 128 bits", nameof(rgbIV));

        var block = _blockFactory(rgbKey);
        return BeltHash.BelTCbcDecryptTransform(block, rgbIV);
    }

    // Эти методы обязательны для реализации абстрактного класса
    public override void GenerateKey()
    {
        //TODO: Необходимо будет создать когда реализую рандомайзер
        throw new NotImplementedException();
        //KeyValue = RandomNumberGenerator.GetBytes(KeySizeValue / 8);
    }

    public override void GenerateIV()
    {
        //TODO: Необходимо будет создать когда реализую рандомайзер
        throw new NotImplementedException();
        //IVValue = RandomNumberGenerator.GetBytes(BlockSizeValue / 8);
    }
}
