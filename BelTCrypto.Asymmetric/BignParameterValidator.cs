using BelTCrypto.Bign.Models;
using System.Numerics;

namespace BelTCrypto.Bign;

public class BignParameterValidator
{
    /// <summary>
    /// Базовая проверка входных данных согласно п. 6.1.1
    /// </summary>
    public static BignValidationResult ValidateBasicConstraints(BignCurveParameters par)
    {
        // 1. Проверка уровня стойкости и модуля p
        // 2^(2l-1) < p < 2^(2l)
        BigInteger minP = BigInteger.One << (2 * par.L - 1);
        BigInteger maxP = BigInteger.One << (2 * par.L);

        if (par.P <= minP || par.P >= maxP)
            return new(false, "Модуль p не соответствует уровню стойкости l.");

        // 2. p ≡ 3 (mod 4)
        if (par.P % 4 != 3)
            return new(false, "Модуль p должен быть равен 3 по модулю 4.");

        // 3. 0 < a < p и 0 < b < p
        if (par.A <= 0 || par.A >= par.P)
            return new(false, "Коэффициент a должен быть в диапазоне (0, p).");

        if (par.B <= 0 || par.B >= par.P)
            return new(false, "Коэффициент b должен быть в диапазоне (0, p).");

        // 4. Проверка порядка q (аналогично p)
        if (par.Q <= minP || par.Q >= maxP)
            return new(false, "Порядок q не соответствует уровню стойкости l.");

        // 5. Проверка дискриминанта (4a^3 + 27b^2 != 0 mod p)
        // Это гарантирует, что кривая не является сингулярной
        if (IsSingular(par))
            return new(false, "Кривая является сингулярной (вырожденной).");

        return new(true);
    }

    private static bool IsSingular(BignCurveParameters par)
    {
        var a3 = BigInteger.ModPow(par.A, 3, par.P);
        var b2 = BigInteger.ModPow(par.B, 2, par.P);
        var res = (4 * a3 + 27 * b2) % par.P;
        return res == 0;
    }
}
