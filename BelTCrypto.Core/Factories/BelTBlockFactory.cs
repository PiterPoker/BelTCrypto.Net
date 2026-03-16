using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTBlockFactory
{
    public static IBelTBlock Create() => new BelTBlock();
    public static IBelTWideBlock CreateWide() => new BelTWideBlock(new BelTBlock());
}