using System.Security.Cryptography;

namespace BelTCrypto.Net;

public static class BelTModes
{
    // Используем 6, так как 1-5 уже заняты в .NET
    public const CipherMode CTR = (CipherMode)6;
}