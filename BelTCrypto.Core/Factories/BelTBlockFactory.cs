using BelTCrypto.Core.Interfaces;
using BelTCrypto.Core.Interfaces.Old;

namespace BelTCrypto.Core.Factories;

public static class BelTBlockFactory
{
    public static IBelTBlock Create() => new BelTBlock();
    public static IBelTWideBlock CreateWide() => new BelTWideBlock(new BelTBlock());
}