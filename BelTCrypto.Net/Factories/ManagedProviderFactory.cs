using BelTCrypto.Core.Interfaces;
using BelTCrypto.Net.Interfaces;
using BelTCrypto.Net.Providers;

namespace BelTCrypto.Net.Factories;

public static class ManagedProviderFactory
{
    public static IManagedBelTEcbProvider Create(IBelTEcb ecbCore, IKeyQuotaTracker quotaTracker)
    {
        return new ManagedBelTEcbProvider(ecbCore, quotaTracker);
    }
}
