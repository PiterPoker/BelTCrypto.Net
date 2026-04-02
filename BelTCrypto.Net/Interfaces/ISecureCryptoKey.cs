namespace BelTCrypto.Net.Interfaces;

public interface ISecureCryptoKey : IDisposable
{
    Guid Id { get; }

    void UseKey(Action<ReadOnlySpan<byte>> cryptoOperation);
    void UnmaskInto(Span<byte> destination);
}