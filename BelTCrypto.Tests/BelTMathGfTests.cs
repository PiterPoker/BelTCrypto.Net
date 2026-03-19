namespace BelTCrypto.Tests;

using BelTCrypto.Core;
using NUnit.Framework;
using NUnit.Framework.Legacy;
using System.Security.Cryptography;

[TestFixture]
public class BelTMathGfTests
{
    [Test]
    public void Multiply_TableA18_Case1_Success()
    {
        // u = 34904055 11BE3297 1343724C 5AB793E9
        byte[] u = [
            0x34, 0x90, 0x40, 0x55, 0x11, 0xBE, 0x32, 0x97,
            0x13, 0x43, 0x72, 0x4C, 0x5A, 0xB7, 0x93, 0xE9
            ];
        // v = 22481783 8761A9D6 E3EC9689 110FB0F3
        byte[] v = [
            0x22, 0x48, 0x17, 0x83, 0x87, 0x61, 0xA9, 0xD6,
            0xE3, 0xEC, 0x96, 0x89, 0x11, 0x0F, 0xB0, 0xF3
            ];
        // u*v = 0001D107 FC67DE40 04DC2C80 3DFD95C3
        byte[] expected = [
            0x00, 0x01, 0xD1, 0x07, 0xFC, 0x67, 0xDE, 0x40,
            0x04, 0xDC, 0x2C, 0x80, 0x3D, 0xFD, 0x95, 0xC3
            ];

        Span<byte> actual = u.ToArray();
        BelTMath.GfBlock.Multiply(actual, v);

        TestContext.Out.WriteLine($"Actual:   {BitConverter.ToString([.. actual])}");
        TestContext.Out.WriteLine($"Expected mac: {BitConverter.ToString([.. expected])}");

        Assert.That(actual.ToArray(), Is.EqualTo(expected).AsCollection, "First case from Table A.18 failed.");
    }

    [Test]
    public void Multiply_TableA18_Case2_Success()
    {
        // u = 703FCCF0 95EE8DF1 C1ABF8EE 8DF1C1AB
        byte[] u = [
            0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
            0xC1, 0xAB, 0xF8, 0xEE, 0x8D, 0xF1, 0xC1, 0xAB
            ];
        // v = 2055704E 2EDB48FE 87E74075 A5E77EB1
        byte[] v = [
            0x20, 0x55, 0x70, 0x4E, 0x2E, 0xDB, 0x48, 0xFE,
            0x87, 0xE7, 0x40, 0x75, 0xA5, 0xE7, 0x7E, 0xB1
            ];
        // u*v = 4A5C9593 8B3FE8F6 74D59BC1 EB356079
        byte[] expected = [
            0x4A, 0x5C, 0x95, 0x93, 0x8B, 0x3F, 0xE8, 0xF6,
            0x74, 0xD5, 0x9B, 0xC1, 0xEB, 0x35, 0x60, 0x79
            ];

        Span<byte> actual = u.ToArray();
        BelTMath.GfBlock.Multiply(actual, v);

        TestContext.Out.WriteLine($"Actual:   {BitConverter.ToString([.. actual])}");
        TestContext.Out.WriteLine($"Expected mac: {BitConverter.ToString([.. expected])}");

        Assert.That(actual.ToArray(), Is.EqualTo(expected).AsCollection, "Second case from Table A.18 failed.");
    }
}