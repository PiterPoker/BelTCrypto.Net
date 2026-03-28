using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Factories;

public static class BelTDiskEncryptionFactory
{

    public static IDiskEncryption Create(BeltDiskScheme scheme) => scheme switch
    {
        BeltDiskScheme.Bde => new BelTBde(BelTBlockFactory.Create()),
        BeltDiskScheme.Sde => new BelTSde(BelTBlockFactory.Create()),
        _ => throw new CryptographicException($"Режим {scheme} не поддерживается для BelT"),
    };

    public enum BeltDiskScheme
    {
        /// <summary>
        /// Схема 1: belt-Bde
        /// </summary>
        Bde = 1,

        /// <summary>
        /// Схема 2: belt-Sde
        /// </summary>
        Sde = 2
    }
}
