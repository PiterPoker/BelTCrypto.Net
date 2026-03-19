using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTEcbFactory
{
    public static IBelTEcb Create() => new BelTEcb(new BelTBlock());
}
