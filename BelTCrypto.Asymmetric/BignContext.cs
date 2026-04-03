using BelTCrypto.Bign.Models;

namespace BelTCrypto.Bign;

public enum BignSecurityLevel
{
    L128 = 128,
    L192 = 192,
    L256 = 256
}

public class BignContext
{
    public BignSecurityLevel Level { get; }
    public BignCurveParameters Parameters { get; }

    // Длина подписи в байтах: 3 * l бит (для ИЭЦП) или 2 * l + l (в разных вариациях)
    // Для стандартной ЭЦП (Sign/Verify) подпись обычно 3*l бит (раздел 7.1)
    public int SignatureSize => (3 * (int)Level) / 8;

    // Длина хэша в байтах (соответствует l бит стойкости)
    // Однако belt-hash всегда выдает 256 бит, 
    // поэтому для L128 мы используем его целиком, а для L192/L256 - специфично.
    public int HashSize => (int)Level / 8;

    public BignContext(BignSecurityLevel level)
    {
        Level = level;
        Parameters = level switch
        {
            BignSecurityLevel.L128 => BignNamedCurves.GetByOid(BignNamedCurves.OidLevel128),
            BignSecurityLevel.L192 => BignNamedCurves.GetByOid(BignNamedCurves.OidLevel192),
            BignSecurityLevel.L256 => BignNamedCurves.GetByOid(BignNamedCurves.OidLevel256),
            _ => throw new ArgumentOutOfRangeException(nameof(level))
        };
    }
}