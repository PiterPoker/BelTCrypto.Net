using BelTCrypto.Core;
using BelTCrypto.Net;
using System.Security.Cryptography;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTCfbTests
{
    [Test]
    public void Encrypt_Cfb_WithUserProvidedData_ReturnsCorrectResult()
    {
        // Данные из твоего сообщения:

        // K = E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6
        byte[] key = Convert.FromHexString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");

        // S = BE329713 43FC9A48 A02A885F 194B09A1
        byte[] s = Convert.FromHexString("BE32971343FC9A48A02A885F194B09A1");

        // X = B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D 5BE3D612 17B96181 FE6786AD 716B890B
        byte[] x = Convert.FromHexString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");

        // Y = C31E490A 90EFA374 626CC99E 4B7B8540 A6E48685 464A5A06 849C9CA7 69A1B0AE 55C2CC59 39303EC8 32DD2FE1 6C8E5A1B
        string expectedY = "C31E490A90EFA374626CC99E4B7B8540A6E48685464A5A06849C9CA769A1B0AE55C2CC5939303EC832DD2FE16C8E5A1B";

        // Настраиваем алгоритм
        using var algo = new BelTAlgorithm(k => BeltHash.BelTBlock(k));
        algo.Mode = CipherMode.CFB;
        algo.Padding = PaddingMode.None;

        // Создаем шифратор (S передаем как IV)
        using var encryptor = algo.CreateEncryptor(key, s);

        // Выполняем зашифрование
        byte[] actualY = encryptor.TransformFinalBlock(x, 0, x.Length);

        // Проверка
        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }

    [Test]
    public void Decrypt_Cfb_WithUserProvidedData_ReturnsCorrectResult()
    {
        byte[] key = Convert.FromHexString("92BD9B1CE5D141015445FBC95E4D0EF2682080AA227D642F2687F93490405511");
        byte[] s = Convert.FromHexString("7ECDA4D01544AF8CA58450BF66D2E88A");
        byte[] y = Convert.FromHexString("E12BDC1AE28257EC703FCCF095EE8DF1C1AB76389FE678CAF7C6F860D5BB9C4FF33C657B637C306ADD4EA7799EB23D31");
        string expectedX = "FA9D107A86F375EE65CD1DB881224BD016AFF814938ED39B3361ABB0BF0851B652244EB06842DD4C94AA4500774E40BB";

        using var algo = new BelTAlgorithm(k => BeltHash.BelTBlock(k));
        algo.Mode = CipherMode.CFB;

        using var decryptor = algo.CreateDecryptor(key, s);
        byte[] actualX = decryptor.TransformFinalBlock(y, 0, y.Length);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX));
    }
}