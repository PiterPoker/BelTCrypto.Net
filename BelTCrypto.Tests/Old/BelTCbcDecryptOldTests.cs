using BelTCrypto.Core.Interfaces.Old;
using BelTCrypto.Core.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Tests.Old;

[TestFixture]
public class BelTCbcDecryptOldTests
{
    // Вспомогательный метод для расшифрования через стандартные потоки
    private byte[] DecryptThroughStream(IBelTBlockOld block, byte[] iv, byte[] ciphertext)
    {
        using var decryptor = BeltHashOld.BelTCbcDecryptTransform(block, iv);
        using var msInput = new MemoryStream(ciphertext);
        using var msOutput = new MemoryStream();

        using (var cs = new CryptoStream(msOutput, decryptor, CryptoStreamMode.Write))
        {
            cs.Write(ciphertext, 0, ciphertext.Length);
            cs.FlushFinalBlock();
        }

        return msOutput.ToArray();
    }

    [Test]
    public void Decrypt_Cbc_StandardVector_FullBlocks_TableA12_Part1()
    {
        // Данные из Таблицы А.12 (часть 1 - 48 байт)
        byte[] key = Convert.FromHexString("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] s = Convert.FromHexString("7ECDA4D01544AF8CA58450BF66D2E88A");
        byte[] y = Convert.FromHexString("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799EB23D31");
        string expectedX = "730894D6158E17CC1600185A8F411CAB0471FF85C83792398D8924EBD57D03DB95B97A9B7907E4B020960455E46176F8";

        var block = BeltHashOld.BelTBlock(key);
        byte[] actualX = DecryptThroughStream(block, s, y);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX), "Расшифрование полных блоков (48 байт) не совпало.");
    }

    [Test]
    public void Decrypt_Cbc_StandardVector_CTS_TableA12_Part2()
    {
        // Данные из Таблицы А.12 (часть 2 - 36 байт)
        // K и S те же
        byte[] key = Convert.FromHexString("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] s = Convert.FromHexString("7ECDA4D01544AF8CA58450BF66D2E88A");

        // Y = 36 байт
        byte[] y = Convert.FromHexString("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B");
        // X = 36 байт
        string expectedX = "730894D6158E17CC1600185A8F411CABB6AB7AF8541CF85755B8EA27239F08D2166646E4";

        var block = BeltHashOld.BelTBlock(key);
        byte[] actualX = DecryptThroughStream(block, s, y);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(actualX, Has.Length.EqualTo(36), "Длина расшифрованного текста должна быть 36 байт.");
            Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX), "Расшифрование в режиме CTS (36 байт) не совпало.");
        }
    }
}
