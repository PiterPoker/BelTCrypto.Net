using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public class BelTCbcFactory
{
    public static IBelTCbc Create() => new BelTCbc(new BelTBlock());
}
