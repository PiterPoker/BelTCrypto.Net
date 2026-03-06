using BelTCrypto.Core;
using BelTCrypto.Net;
using System.Security.Cryptography;

namespace BelTCrypto.Tests;

internal class BelTAlgorithmTests
{
    [Test]
    public void BelTAlgorithm_Ecb_IntegrationTest()
    {
        // Данные из Таблицы А.9
        byte[] key = Convert.FromHexString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] x = Convert.FromHexString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B89");
        string expectedY = "69CCA1C93557C9E3D66BC3E0FA88FA6E36F00CFED6D1CA1498C12798F4BEB2075F23102EF109710775017F73806DA9";

        // 1. Создаем алгоритм
        using var algo = new BelTAlgorithm(k => BeltHash.BelTBlock(k));
        algo.Mode = CipherMode.ECB; // Переключаем режим
        algo.Padding = PaddingMode.None;

        // 2. Создаем шифратор через стандартный метод
        using var encryptor = algo.CreateEncryptor(key, null);

        // 3. Проверяем результат
        byte[] actualY = encryptor.TransformFinalBlock(x, 0, x.Length);

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY));
    }

    [Test]
    public void BelTAlgorithm_Cbc_CryptoStream_Integration()
    {
        // Данные из Таблицы А.11
        byte[] key = Convert.FromHexString("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] iv = Convert.FromHexString("BE32971343FC9A48A02A885F194B09A1");
        byte[] x = Convert.FromHexString("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D612");
        string expectedY = "10116EFAE6AD58EE14852E11DA1B8A746A9BBADCAF73F968F875DEDC0A44F6B15CF2480E";

        using var algo = new BelTAlgorithm(k => BeltHash.BelTBlock(k));
        algo.Mode = CipherMode.CBC;

        using var ms = new MemoryStream();
        // Используем алгоритм как стандартный .NET объект
        using (var encryptor = algo.CreateEncryptor(key, iv))
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(x, 0, x.Length);
            cs.FlushFinalBlock();
        }

        Assert.That(Convert.ToHexString(ms.ToArray()), Is.EqualTo(expectedY));
    }
}
