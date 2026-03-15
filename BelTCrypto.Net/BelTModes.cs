using System.Security.Cryptography;

namespace BelTCrypto.Net;

public static class BelTModes
{
    public const CipherMode CBC = CipherMode.CBC;
    public const CipherMode ECB = CipherMode.ECB;
    public const CipherMode CFB = CipherMode.CFB;
    public const CipherMode CTS = CipherMode.CTS;
    // Используем 6, так как 1-5 уже заняты в .NET
    public const CipherMode CTR = (CipherMode)6;
}
public enum BeltAeadScheme
{
    /// <summary>
    /// Схема 1: belt-dwp (п. 7.6.3)
    /// </summary>
    Dwp = 1,

    /// <summary>
    /// Схема 2: belt-che (п. 7.6.5)
    /// </summary>
    Che = 2
}