namespace BelTCrypto.Net.Interfaces
{
    public interface ISessionKeyManager
    {
        ISecureCryptoKey CurrentKey { get; }

        void RotateKey();
    }
}