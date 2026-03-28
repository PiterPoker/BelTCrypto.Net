using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTHashFactory
{
    public static IBelTHash Create() => new BelTHash(BelTCompressorFactory.Create());
}
