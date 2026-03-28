using BelTCrypto.Core.Old;
using System.Security.Cryptography;

namespace BelTCrypto.Tests.Old;

[TestFixture]
public class BelTCbcEncryptOldTests
{
    private static byte[] StringToByteArray(string hex)
    {
        hex = hex.Replace(" ", ""); // Убираем пробелы, если они есть
        return [.. Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))];
    }

    [Test]
    public void Encrypt_Cbc_StandardVector_FullBlocks_TableA11_Part1()
    {
        // Данные из первой части Таблицы А.11 (48 байт)
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] s = StringToByteArray("BE32971343FC9A48A02A885F194B09A1");
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B");
        string expectedY = "10116EFAE6AD58EE14852E11DA1B8A745CF2480E8D03F1C19492E53ED3A70F60657C1EE8C0E0AE5B58388BF8A68E3309";

        var block = BeltHashOld.BelTBlock(key);
        var transform = BeltHashOld.BelTCbcEncryptTransform(block, s);

        // 3. Шифрование через поток
        using var msInput = new MemoryStream(x);
        using var msOutput = new MemoryStream();

        // CryptoStreamMode.Read или Write — не важно, главное прогнать данные
        using (var cs = new CryptoStream(msOutput, transform, CryptoStreamMode.Write))
        {
            cs.Write(x, 0, x.Length);
            cs.FlushFinalBlock(); // Обязательно! Это вызовет TransformFinalBlock
        }

        byte[] actualY = msOutput.ToArray();

        // 4. Проверка
        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY), "Full block encryption failed.");
    }

    [Test]
    public void Encrypt_Cbc_StandardVector_PartialBlock_TableA11_Part2()
    {
        // Данные из второй части Таблицы А.11 (41 байт)
        byte[] key = StringToByteArray("E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6");
        byte[] s = StringToByteArray("BE32971343FC9A48A02A885F194B09A1");
        byte[] x = StringToByteArray("B194BAC80A08F53B366D008E584A5DE48504FA9D1BB6C7AC252E72C202FDCE0D5BE3D612");
        string expectedY = "10116EFAE6AD58EE14852E11DA1B8A746A9BBADCAF73F968F875DEDC0A44F6B15CF2480E";


        var block = BeltHashOld.BelTBlock(key);
        var transform = BeltHashOld.BelTCbcEncryptTransform(block, s);

        // 3. Шифрование через поток
        using var msInput = new MemoryStream(x);
        using var msOutput = new MemoryStream();

        // CryptoStreamMode.Read или Write — не важно, главное прогнать данные
        using (var cs = new CryptoStream(msOutput, transform, CryptoStreamMode.Write))
        {
            cs.Write(x, 0, x.Length);
            cs.FlushFinalBlock(); // Обязательно! Это вызовет TransformFinalBlock
        }

        byte[] actualY = msOutput.ToArray();

        Assert.That(Convert.ToHexString(actualY), Is.EqualTo(expectedY), "Partial block (CTS) encryption failed.");
    }
}