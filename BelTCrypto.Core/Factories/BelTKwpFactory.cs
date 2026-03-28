using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTKwpFactory
{
    public static IBelTKwp Create() => new BelTKwp(BelTBlockFactory.CreateWide());
}
