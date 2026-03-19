using BelTCrypto.Core;
using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
public class BelTMacTests
{
    private IBelTMac _mac;

    [SetUp]
    public void Setup()
    {
        _mac = BelTMacFactory.Create();
    }

    [Test]
    public void Compute_TableA17_PartialBlock_Success()
    {
        // Тест 1: Неполный блок (13 байт)
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..13];
        var expectedT = new byte[]
        {
            0x72, 0x60, 0xDA, 0x60, 0x13, 0x8F, 0x96, 0xC9
        };

        Span<byte> actualT = stackalloc byte[8];
        _mac.Compute(x, k, actualT);

        TestContext.Out.WriteLine($"Actual mac:   {BitConverter.ToString(actualT.ToArray())}");
        TestContext.Out.WriteLine($"Expected mac: {BitConverter.ToString(expectedT)}");

        Assert.That(actualT.ToArray(), Is.EqualTo(expectedT), "MAC failed for partial block");
    }

    [Test]
    public void Compute_TableA17_FullBlocks_Success()
    {
        // Тест 2: Три полных блока (48 байт)
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..48];
        var expectedT = new byte[]
        {
            0x2D, 0xAB, 0x59, 0x77, 0x1B, 0x4B, 0x16, 0xD0
        };


        Span<byte> actualT = stackalloc byte[8];
        _mac.Compute(x, k, actualT);

        TestContext.Out.WriteLine($"Actual mac:   {BitConverter.ToString(actualT.ToArray())}");
        TestContext.Out.WriteLine($"Expected mac: {BitConverter.ToString(expectedT)}");

        Assert.That(actualT.ToArray(), Is.EqualTo(expectedT), "MAC failed for multiple full blocks");
    }

    [Test]
    public void Verify_ValidMac_ReturnsTrue()
    {
        var k = Core.BelTMath.H[128..160];
        var x = Core.BelTMath.H[..48];
        var validMac = new byte[]
        {
            0x2D, 0xAB, 0x59, 0x77, 0x1B, 0x4B, 0x16, 0xD0
        };

        bool isValid = _mac.Verify(x, k, validMac);

        Assert.That(isValid, Is.True, "Verification should pass for correct MAC");
    }
}
