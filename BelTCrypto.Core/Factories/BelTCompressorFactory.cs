using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core.Factories;


public static class BelTCompressorFactory
{
    public static IBelTCompress Create() => new BelTCompressor(new BelTBlock());
}
