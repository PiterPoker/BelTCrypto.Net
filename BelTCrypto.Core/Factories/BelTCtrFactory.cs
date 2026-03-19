using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTCtrFactory
{
    public static IBelTCtr Create() => new BelTCtr(new BelTBlock());
}
