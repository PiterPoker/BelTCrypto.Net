using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BeltFmtFactory
{
    public static IBelTFmt Create() => new BelTFmt(BelTBlockFactory.Create(), BelTBlockFactory.CreateWide());
}
