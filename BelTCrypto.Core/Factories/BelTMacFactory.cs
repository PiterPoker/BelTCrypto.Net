using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTMacFactory
{
    public static IBelTMac Create() => new BelTMac(new BelTBlock());
}
