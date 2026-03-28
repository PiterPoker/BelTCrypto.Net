using BelTCrypto.Core.Factories;
using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Tests;

[TestFixture]
internal class BelTHashTests
{
    private IBelTHash _hash;

    [SetUp]
    public void Setup() => _hash = BelTHashFactory.Create();

    [Test]
    public void Hash_TableA23_Vector1_Short()
    {
        // X = B194BAC8 0A08F53B 366D008E 58 (13 байт)
        var x = Core.BelTMath.H[..13];

        var expectedY = new byte[]
        {
            0xAB, 0xEF, 0x97, 0x25, 0xD4, 0xC5, 0xA8, 0x35, 
            0x97, 0xA3, 0x67, 0xD1, 0x44, 0x94, 0xCC, 0x25, 
            0x42, 0xF2, 0x0F, 0x65, 0x9D, 0xDF, 0xEC, 0xC9, 
            0x61, 0xA3, 0xEC, 0x55, 0x0C, 0xBA, 0x8C, 0x75
        };

        var actualY = new byte[32];
        _hash.ComputeHash(x, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "Hash Vector 1 (Short) failed");
    }

    [Test]
    public void Hash_TableA23_Vector2_FullBlock()
    {
        // X = B194BAC8 0A08F53B 366D008E 584A5DE4 8504FA9D 1BB6C7AC 252E72C2 02FDCE0D (32 байта)
        var x = Core.BelTMath.H[..32];

        var expectedY = new byte[]
        {
            0x74, 0x9E, 0x4C, 0x36, 0x53, 0xAE, 0xCE, 0x5E, 
            0x48, 0xDB, 0x47, 0x61, 0x22, 0x77, 0x42, 0xEB, 
            0x6D, 0xBE, 0x13, 0xF4, 0xA8, 0x0F, 0x7B, 0xEF, 
            0xF1, 0xA9, 0xCF, 0x8D, 0x10, 0xEE, 0x77, 0x86
        };

        var actualY = new byte[32];
        _hash.ComputeHash(x, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "Hash Vector 2 (Full Block) failed");
    }

    [Test]
    public void Hash_TableA23_Vector3_Long()
    {
        // X = B194BAC8...02FDCE0D (32 байта) + 5BE3D612 17B96181 FE6786AD 716B890B (12 байт) = 44 байта
        var x = Core.BelTMath.H[..48];

        var expectedY = new byte[]
        {
            0x9D, 0x02, 0xEE, 0x44, 0x6F, 0xB6, 0xA2, 0x9F, 
            0xE5, 0xC9, 0x82, 0xD4, 0xB1, 0x3A, 0xF9, 0xD3, 
            0xE9, 0x08, 0x61, 0xBC, 0x4C, 0xEF, 0x27, 0xCF, 
            0x30, 0x6B, 0xFB, 0x0B, 0x17, 0x4A, 0x15, 0x4A
        };

        var actualY = new byte[32];
        _hash.ComputeHash(x, actualY);

        TestContext.Out.WriteLine($"Actual Y:   {BitConverter.ToString(actualY)}");
        TestContext.Out.WriteLine($"Expected Y: {BitConverter.ToString(expectedY)}");

        Assert.That(actualY, Is.EqualTo(expectedY), "Hash Vector 3 (Long) failed");
    }
}