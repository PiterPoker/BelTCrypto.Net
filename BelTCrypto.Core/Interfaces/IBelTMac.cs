namespace BelTCrypto.Core.Interfaces;

public interface IBelTMac : IDisposable
{
    void Reset();
    byte[] Finalize(ReadOnlySpan<byte> lastChunk, int length);
    void ProcessBlock(ReadOnlySpan<byte> block);
}
