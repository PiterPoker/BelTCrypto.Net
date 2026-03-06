using BelTCrypto.Core;
using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public class BelTAlgorithm : SymmetricAlgorithm
{
    private readonly Func<byte[], IBelTBlock> _blockFactory;

    public BelTAlgorithm(Func<byte[], IBelTBlock> blockFactory)
    {
        _blockFactory = blockFactory;

        // Общие параметры для всех режимов BelT
        LegalKeySizesValue = [new KeySizes(128, 256, 64)];
        LegalBlockSizesValue = [new KeySizes(128, 128, 0)];
        KeySizeValue = 256;
        BlockSizeValue = 128;

        // По умолчанию ставим CBC, как самый частый
        ModeValue = CipherMode.CBC;
        PaddingValue = PaddingMode.None;
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        var block = _blockFactory(rgbKey);

        // Вот здесь происходит переключение режимов
        return Mode switch
        {
            CipherMode.ECB => BeltHash.BelTEcbEncryptTransform(block),
            CipherMode.CBC => BeltHash.BelTCbcEncryptTransform(block, rgbIV ?? IV),
            CipherMode.CFB => BeltHash.BelTCfbEncryptTransform(block, rgbIV ?? IV),
            // Сюда потом добавим CTR, CFB и т.д.
            _ => throw new CryptographicException($"Режим {Mode} не поддерживается для BelT")
        };
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        var block = _blockFactory(rgbKey);

        return Mode switch
        {
            CipherMode.ECB => BeltHash.BelTEcbDecryptTransform(block),
            CipherMode.CBC => BeltHash.BelTCbcDecryptTransform(block, rgbIV ?? IV),
            CipherMode.CFB => BeltHash.BelTCfbDecryptTransform(block, rgbIV ?? IV),
            _ => throw new CryptographicException($"Режим {Mode} не поддерживается для BelT")
        };
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