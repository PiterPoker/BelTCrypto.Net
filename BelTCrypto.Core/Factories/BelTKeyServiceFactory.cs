using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;

public static class BelTKeyServiceFactory
{
    public static IBelTKeyService Create() => new BelTKeyService(BelTCompressorFactory.Create());
}
