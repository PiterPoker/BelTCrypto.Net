namespace BelTCrypto.Tests;

[TestFixture]
public class BelTDwpTests
{
    // Тестовые векторы из А.19 (в формате СТБ)
    private const string K_HEX = "E9DEE72C8F0C0FA62DDB49F46F73964706075316ED247A3739CBA38303A98BF6";
    private const string S_HEX = "BE32971343FC9A48A02A885F194B09A1";
    private const string I_HEX = "8504FA9D1BB6C7AC252E72C202FDCE0D5BE3D61217B96181FE6786AD716B890B";


    [Test]
    public void BeltDwp_Protect_TableA19_Test()
    {
    // Результаты А.19
    const string X_HEX = "B194BAC80A08F53B366D008E584A5DE4";
    const string Y_EXPECTED = "52C9AF96FF50F64435FC43DEF56BD797";
    const string T_EXPECTED = "3B2E0AEB2B91854B";
    byte[] K = Convert.FromHexString(K_HEX);
        byte[] S = Convert.FromHexString(S_HEX);
        byte[] I = Convert.FromHexString(I_HEX);
        byte[] X = Convert.FromHexString(X_HEX);

        using var belt = new BelTCrypto.Net.BeltAead(K, BelTCrypto.Net.BeltAeadScheme.Dwp);

        byte[] actualY = new byte[X.Length];
        byte[] actualT = new byte[8];

        belt.Encrypt(S, X, actualY, actualT, I);

        Assert.Multiple(() =>
        {
            Assert.That(Convert.ToHexString(actualY), Is.EqualTo(Y_EXPECTED), "Шифртекст Y не совпадает");
            Assert.That(Convert.ToHexString(actualT), Is.EqualTo(T_EXPECTED), "Имитовставка T не совпадает");
        });
    }

    [Test]
    public void BeltDwp_Unprotect_TableA20_Test()
    {
        // Данные из таблицы А.20
        byte[] K = Convert.FromHexString(K_HEX);
        byte[] S = Convert.FromHexString(S_HEX);
        byte[] I = Convert.FromHexString(I_HEX);

        byte[] Y = Convert.FromHexString("E12BDC1AE28257EC703FCCF095EE8DF1");
        byte[] T = Convert.FromHexString("6A2C2C94C4150DC0");
        string expectedX = "DF181ED008A20F43DCBBB93650DAD34B";

        using var belt = new BelTCrypto.Net.BeltAead(K, BelTCrypto.Net.BeltAeadScheme.Dwp);
        byte[] actualX = new byte[Y.Length];

        belt.Decrypt(S, Y, T, actualX, I);

        Assert.That(Convert.ToHexString(actualX), Is.EqualTo(expectedX));
    }
}