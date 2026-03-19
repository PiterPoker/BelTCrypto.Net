using BelTCrypto.Core.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Core.Factories;

public static class BelTAuthenticatedFactory
{
    public static IBelTDwp Create()
    {
        return new BelTDwp(new BelTBlock());
    }

    public static IAuthenticatedEncryption Create(BeltAeadScheme scheme) => scheme switch
    {
        BeltAeadScheme.Dwp => new BelTDwp(new BelTBlock()),
        BeltAeadScheme.Che => throw new NotImplementedException(),
        _ => throw new CryptographicException($"Режим {scheme} не поддерживается для BelT"),
    };

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
}
