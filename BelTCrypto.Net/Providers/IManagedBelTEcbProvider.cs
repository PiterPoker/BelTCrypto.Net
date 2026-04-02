using BelTCrypto.Net.Interfaces;

namespace BelTCrypto.Net.Providers
{
    public interface IManagedBelTEcbProvider
    {
        void Decrypt(ReadOnlySpan<byte> data, ISecureCryptoKey key, Span<byte> output);
        void Encrypt(ReadOnlySpan<byte> data, ISecureCryptoKey key, Span<byte> output);
    }
}