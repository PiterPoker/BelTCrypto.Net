using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using System.Security.Cryptography;

namespace BelTCrypto.Net.Factories;

public static class SecureCryptoKeyFactory
{
    public static ISecureCryptoKey Create(ReadOnlySpan<byte> keyMaterial, Guid? id = null)
    {
        return new SecureCryptoKey(keyMaterial, id);
    }
}

public static class SessionKeyManagerFactory
{
    public static ISessionKeyManager Create(ISecureCryptoKey masterKey, IBelTKeyService keyService, ReadOnlySpan<byte> sessionNonce)
    {
        return new SessionKeyManager(masterKey, keyService, sessionNonce);
    }
}

public static class KeyQuotaTrackerFactory
{
    public static IKeyQuotaTracker Create()
    {
        return new InMemoryQuotaTracker();
    }
}
