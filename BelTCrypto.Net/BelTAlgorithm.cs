using BelTCrypto.Core.Interfaces.Old;
using BelTCrypto.Core.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Net;

public class BelTAlgorithm : SymmetricAlgorithm
{
    private readonly Func<byte[], IBelTBlockOld> _blockFactory;

    public BelTAlgorithm(Func<byte[], IBelTBlockOld> blockFactory)
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
            CipherMode.ECB => BeltHashOld.BelTEcbEncryptTransform(block),
            CipherMode.CBC => BeltHashOld.BelTCbcEncryptTransform(block, rgbIV ?? IV),
            CipherMode.CFB => BeltHashOld.BelTCfbEncryptTransform(block, rgbIV ?? IV),
            BelTModes.CTR => BeltHashOld.BelTCtrTransform(block, rgbIV ?? IV),
            // Сюда потом добавим CTR, CFB и т.д.
            _ => throw new CryptographicException($"Режим {Mode} не поддерживается для BelT")
        };
    }

    public override CipherMode Mode
    {
        get => ModeValue;
        set
        {
            if (!(value == CipherMode.CBC ||
                  value == CipherMode.ECB ||
                  value == CipherMode.CFB ||
                  value == BelTModes.CTR)) 
            {
                throw new CryptographicException("Указанный режим шифрования не поддерживается для BelT");
            }

            ModeValue = value;
        }
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
    {
        var block = _blockFactory(rgbKey);

        return Mode switch
        {
            CipherMode.ECB => BeltHashOld.BelTEcbDecryptTransform(block),
            CipherMode.CBC => BeltHashOld.BelTCbcDecryptTransform(block, rgbIV ?? IV),
            CipherMode.CFB => BeltHashOld.BelTCfbDecryptTransform(block, rgbIV ?? IV),
            BelTModes.CTR => BeltHashOld.BelTCtrTransform(block, rgbIV ?? IV),
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