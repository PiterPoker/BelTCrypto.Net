namespace BelTCrypto.Core.Interfaces.Old;

public interface IBelTMacOld : IDisposable
{
    void Reset();
    byte[] Finalize(ReadOnlySpan<byte> lastChunk, int length);
    void ProcessBlock(ReadOnlySpan<byte> block);
}
