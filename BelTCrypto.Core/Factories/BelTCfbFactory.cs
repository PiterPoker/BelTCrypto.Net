using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTCfbFactory
{
    public static IBelTCfb Create() => new BelTCfb(new BelTBlock());
}
