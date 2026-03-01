using System.Buffers.Binary;

namespace BelTCrypto.Core;

public sealed class BelTWideBlock(BelTBlock block)
{
    private readonly BelTBlock _block = block ?? throw new ArgumentNullException(nameof(block));
    public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        // 1. Установить r <- X
        int totalLen = input.Length;
        byte[] r = new byte[totalLen];
        input.CopyTo(r);

        // n — количество блоков по 16 байт (последний может быть неполным)
        int n = (totalLen + 15) / 16;

        byte[] s = new byte[16];
        byte[] beltBlockS = new byte[16];

        // 3. Цикл i = 1 to 2n
        for (int i = 1; i <= 2 * n; i++)
        {
            // 3.1) s <- r1 ^ r2 ^ ... ^ rn-1
            // XOR-им все блоки, кроме последнего r_n
            Array.Clear(s, 0, 16);
            for (int j = 0; j < n - 1; j++)
            {
                for (int b = 0; b < 16; b++)
                {
                    s[b] ^= r[j * 16 + b];
                }
            }

            // 3.2) r* <- r* ^ belt-block(s, K) ^ <i>128
            // r* — это последние 16 байт строки r
            _block.Encrypt(s, beltBlockS);
            uint iUint = (uint)i;

            int rStarStart = totalLen - 16;
            for (int b = 0; b < 16; b++)
            {
                byte stepConst = (b < 4) ? (byte)((iUint >> (b * 8)) & 0xFF) : (byte)0;
                r[rStarStart + b] ^= (byte)(beltBlockS[b] ^ stepConst);
            }

            // 3.3) r <- ShLo128(r)
            // Циклический сдвиг всей строки r на 16 байт ВЛЕВО.
            // Первые 16 байт (r1) уходят в конец.
            byte[] r1 = new byte[16];
            Array.Copy(r, 0, r1, 0, 16);
            Array.Copy(r, 16, r, 0, totalLen - 16);

            // Записываем r1 в самый хвост (последние 16 байт)
            // Если длина не кратна 16, r1 "затрет" часть предыдущих данных в конце
            r1.CopyTo(r.AsSpan(totalLen - 16));

            // 3.4) r* <- s
            // Последние 16 байт строки r заменяются на s
            s.CopyTo(r.AsSpan(totalLen - 16));
        }

        // 4. Y <- r
        r.CopyTo(output);
    }

    public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        // 1. Установить r <- Y
        int totalLen = input.Length;
        byte[] r = new byte[totalLen];
        input.CopyTo(r);

        int n = (totalLen + 15) / 16;
        byte[] s = new byte[16];
        byte[] beltBlockS = new byte[16];

        // 3. Для i = 2n, ..., 1 выполнить:
        for (int i = 2 * n; i >= 1; i--)
        {
            // 3.1) s <- r* (r* — это последние 16 байт строки r)
            Array.Copy(r, totalLen - 16, s, 0, 16);

            // 3.2) r <- ShHi128(r) (Циклический сдвиг всей строки ВПРАВО на 16 байт)
            byte[] last16 = new byte[16];
            Array.Copy(r, totalLen - 16, last16, 0, 16);

            // Сдвигаем данные вправо
            Array.Copy(r, 0, r, 16, totalLen - 16);

            // Переносим хвост в начало (r1 <- старый r*)
            last16.CopyTo(r.AsSpan(0, 16));

            // 3.3) r* <- r* ^ belt-block(s, K) ^ <i>128
            // Теперь r* — это снова последние 16 байт ПОСЛЕ сдвига
            _block.Encrypt(s, beltBlockS);
            uint iUint = (uint)i;

            int rStarStart = totalLen - 16;
            for (int b = 0; b < 16; b++)
            {
                byte stepConst = (b < 4) ? (byte)((iUint >> (b * 8)) & 0xFF) : (byte)0;
                r[rStarStart + b] ^= (byte)(beltBlockS[b] ^ stepConst);
            }

            // 3.4) r1 <- s ^ r2 ^ ... ^ rn-1
            // XOR-им все блоки кроме первого (r1) и последнего (rn)
            // ВНИМАНИЕ: стандарт говорит XOR-ить r2...rn-1.
            byte[] xorSum = new byte[16];
            // Копируем s как базу для восстановления r1
            s.CopyTo(xorSum, 0);

            for (int j = 1; j < n - 1; j++)
            {
                for (int b = 0; b < 16; b++)
                {
                    xorSum[b] ^= r[j * 16 + b];
                }
            }

            // Записываем результат в r1 (первые 16 байт)
            xorSum.CopyTo(r.AsSpan(0, 16));
        }

        // 4. Установить X <- r
        r.CopyTo(output);
    }
}
