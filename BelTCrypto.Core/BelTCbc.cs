using BelTCrypto.Core.Interfaces;

namespace BelTCrypto.Core;

internal class BelTCbc : IBelTCbc
{
    private IBelTBlock _block;

    public BelTCbc(IBelTBlock block)
    {
        _block = block ?? throw new ArgumentNullException(nameof(block));
    }

    public void Decrypt(ReadOnlySpan<byte> y, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> x)
    {
        int totalLen = y.Length;
        if (totalLen < 16)
            throw new ArgumentException("Длина сообщения Y должна быть не меньше 128 бит.");

        int n = (totalLen + 15) / 16;
        int mBytes = totalLen % 16;

        // Шаг 2: Y0 = S
        Span<byte> prevY = stackalloc byte[16];
        s.CopyTo(prevY);

        try
        {
            // Шаг 3: Если сообщение кратно 128 битам (m = 0)
            if (mBytes == 0)
            {
                for (int i = 0; i < n; i++)
                {
                    var yi = y.Slice(i * 16, 16);
                    var xi = x.Slice(i * 16, 16);

                    // Xi ← belt-block⁻¹(Yi, K)
                    _block.Decrypt(yi, k, xi);

                    // Xi ← Xi ⊕ Yi−1
                    BelTMath.GfBlock.Xor(xi, prevY);

                    // Обновляем Yi-1 для следующего шага
                    yi.CopyTo(prevY);
                }
            }
            // Шаг 4: Иначе, если |Yn| < 128 (m != 0)
            else
            {
                // 4.1) Блоки 1...n-2 (стандартный CBC)
                for (int i = 0; i < n - 2; i++)
                {
                    var yi = y.Slice(i * 16, 16);
                    var xi = x.Slice(i * 16, 16);

                    _block.Decrypt(yi, k, xi);
                    BelTMath.GfBlock.Xor(xi, prevY);
                    yi.CopyTo(prevY);
                }

                // Индексы для последних двух блоков
                int idxPrev = (n - 2) * 16; // Позиция Yn-1
                int idxLast = (n - 1) * 16; // Позиция Yn

                // Временный буфер для промежуточных вычислений
                Span<byte> temp = stackalloc byte[16];
                Span<byte> ynWithZero = stackalloc byte[16];

                // 4.2) (Xn ‖ r) ← belt-block⁻¹(Yn−1, K) ⊕ (Yn ‖ 0)
                _block.Decrypt(y.Slice(idxPrev, 16), k, temp);

                // Формируем (Yn || 0)
                y.Slice(idxLast, mBytes).CopyTo(ynWithZero);
                // Остальные байты в ynWithZero уже 0 благодаря stackalloc/Clear

                // Выполняем XOR: получаем (Xn || r)
                BelTMath.GfBlock.Xor(temp, ynWithZero);

                // Копируем Xn в результат
                temp[..mBytes].CopyTo(x.Slice(idxLast, mBytes));

                // Извлекаем r (оставшиеся байты блока)
                ReadOnlySpan<byte> r = temp[mBytes..];

                // 4.3) Xn−1 ← belt-block⁻¹(Yn ‖ r, K) ⊕ Yn−2
                // Используем ynWithZero как буфер для (Yn || r)
                r.CopyTo(ynWithZero[mBytes..]);

                _block.Decrypt(ynWithZero, k, x.Slice(idxPrev, 16));

                // XOR с Yn-2 (который сейчас в prevY)
                BelTMath.GfBlock.Xor(x.Slice(idxPrev, 16), prevY);

                // Очистка временных данных
                temp.Clear();
                ynWithZero.Clear();
            }
        }
        finally
        {
            prevY.Clear();
        }
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y)
    {
        int totalLen = x.Length;
        if (totalLen < 16) throw new ArgumentException("X length < 128 bits");

        int n = (totalLen + 15) / 16;
        int mBytes = totalLen % 16;

        // 2) Обозначить Y0 = S
        Span<byte> rRegister = stackalloc byte[16];
        s.CopyTo(rRegister);

        Span<byte> blockBuffer = stackalloc byte[16];
        try
        {
            // 3) Если |Xn| = 128
            if (mBytes == 0)
            {
                for (int i = 0; i < n; i++)
                {
                    // Yi ← belt-block(Xi ⊕ Yi−1, K)
                    x.Slice(i * 16, 16).CopyTo(blockBuffer);
                    BelTMath.GfBlock.Xor(blockBuffer, rRegister);

                    _block.Encrypt(blockBuffer, k, y.Slice(i * 16, 16));

                    // Обновление Yi-1 для следующего шага
                    y.Slice(i * 16, 16).CopyTo(rRegister);
                }
            }
            // 4) Иначе, если |Xn| < 128
            else
            {
                // 4.1) блоки 1..n-2
                for (int i = 0; i < n - 2; i++)
                {
                    x.Slice(i * 16, 16).CopyTo(blockBuffer);
                    BelTMath.GfBlock.Xor(blockBuffer, rRegister);
                    _block.Encrypt(blockBuffer, k, y.Slice(i * 16, 16));
                    y.Slice(i * 16, 16).CopyTo(rRegister);
                }

                int idxPrev = (n - 2) * 16; // Индекс Xn-1
                int idxLast = (n - 1) * 16; // Индекс Xn

                // 4.2) (Yn ‖ r) ← belt-block(Xn−1 ⊕ Yn−2, K)
                x.Slice(idxPrev, 16).CopyTo(blockBuffer);
                BelTMath.GfBlock.Xor(blockBuffer, rRegister); // rRegister содержит Yn-2

                Span<byte> ynWithR = stackalloc byte[16];
                _block.Encrypt(blockBuffer, k, ynWithR);

                // Копируем Yn в конец выходного массива
                ynWithR[..mBytes].CopyTo(y.Slice(idxLast, mBytes));
                ReadOnlySpan<byte> r = ynWithR[mBytes..];

                // 4.3) Yn−1 ← belt-block((Xn ⊕ Yn) ‖ r, K)
                blockBuffer.Clear();
                x.Slice(idxLast, mBytes).CopyTo(blockBuffer);
                // XOR Xn ^ Yn (Yn уже лежит в y)
                for (int j = 0; j < mBytes; j++)
                    blockBuffer[j] ^= y[idxLast + j];

                // Сцепляем с r
                r.CopyTo(blockBuffer[mBytes..]);

                _block.Encrypt(blockBuffer, k, y.Slice(idxPrev, 16));

                ynWithR.Clear();
            }
        }
        finally
        {
            rRegister.Clear();
            blockBuffer.Clear();
        }
    }
}
