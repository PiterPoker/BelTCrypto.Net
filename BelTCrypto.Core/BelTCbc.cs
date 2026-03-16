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
        if (totalLen < 16) throw new ArgumentException("Длина Y < 128 бит.");

        int n = (totalLen + 15) / 16;
        int mBytes = totalLen % 16;

        Span<byte> prevY = stackalloc byte[16];
        s.CopyTo(prevY);

        try
        {
            if (mBytes == 0)
            {
                // Простая и понятная основная часть
                DecryptFullBlocks(y, x, k, n, prevY);
            }
            else
            {
                // Часть 1: Обработка всех блоков кроме последних двух
                DecryptFullBlocks(y, x, k, n - 2, prevY);

                // Часть 2: Финализация (CTS)
                FinalizeDecryption(y, x, k, n, mBytes, prevY);
            }
        }
        finally
        {
            prevY.Clear();
        }
    }

    private void DecryptFullBlocks(ReadOnlySpan<byte> y, Span<byte> x, ReadOnlySpan<byte> k, int count, Span<byte> prevY)
    {
        for (int i = 0; i < count; i++)
        {
            var yi = y.Slice(i * 16, 16);
            var xi = x.Slice(i * 16, 16);

            _block.Decrypt(yi, k, xi);
            BelTMath.GfBlock.Xor(xi, prevY);
            yi.CopyTo(prevY);
        }
    }

    private void FinalizeDecryption(ReadOnlySpan<byte> y, Span<byte> x, ReadOnlySpan<byte> k, int n, int mBytes, ReadOnlySpan<byte> prevY)
    {
        int idxPrev = (n - 2) * 16;
        int idxLast = (n - 1) * 16;

        // Временные блоки на стеке для полной изоляции
        Span<byte> blockXn = stackalloc byte[16];
        Span<byte> blockXnMinus1 = stackalloc byte[16];
        Span<byte> bufferYnWithR = stackalloc byte[16];
        Span<byte> temp = stackalloc byte[16];

        try
        {
            // 1. Работаем с Yn-1: (Xn || r) = Decrypt(Yn-1) ^ (Yn || 0)
            _block.Decrypt(y.Slice(idxPrev, 16), k, temp);

            // Маскируем хвост нулями для XOR (безопасное чтение хвоста шифртекста)
            Span<byte> ynPadded = stackalloc byte[16];
            y.Slice(idxLast, mBytes).CopyTo(ynPadded);

            BelTMath.GfBlock.Xor(temp, ynPadded);

            // Теперь в temp лежит (Xn || r). Сохраняем это в наш блокXn
            temp.CopyTo(blockXn);
            ReadOnlySpan<byte> r = temp[mBytes..];

            // 2. Готовим (Yn || r) для получения Xn-1
            y.Slice(idxLast, mBytes).CopyTo(bufferYnWithR);
            r.CopyTo(bufferYnWithR[mBytes..]);

            // 3. Получаем Xn-1 = Decrypt(Yn || r) ^ Yn-2
            _block.Decrypt(bufferYnWithR, k, blockXnMinus1);
            BelTMath.GfBlock.Xor(blockXnMinus1, prevY);

            // 4. ФИНАЛЬНЫЙ ЭТАП: Копируем всё в выходной массив
            // Теперь неважно, совпадает ли x с y, данные уже в безопасности на стеке
            blockXnMinus1.CopyTo(x.Slice(idxPrev, 16));
            blockXn[..mBytes].CopyTo(x.Slice(idxLast, mBytes));
        }
        finally
        {
            // Очистка всех следов
            blockXn.Clear();
            blockXnMinus1.Clear();
            bufferYnWithR.Clear();
            temp.Clear();
        }
    }

    public void Encrypt(ReadOnlySpan<byte> x, ReadOnlySpan<byte> k, ReadOnlySpan<byte> s, Span<byte> y)
    {
        int totalLen = x.Length;
        if (totalLen < 16) throw new ArgumentException("X length < 128 bits");

        int n = (totalLen + 15) / 16;
        int mBytes = totalLen % 16;

        Span<byte> rRegister = stackalloc byte[16];
        s.CopyTo(rRegister);

        try
        {
            if (mBytes == 0)
            {
                EncryptFullBlocks(x, y, k, n, rRegister);
            }
            else
            {
                // Часть 1: Стандартная цепочка для первых n-2 блоков
                EncryptFullBlocks(x, y, k, n - 2, rRegister);

                // Часть 2: Финализация методом кражи шифртекста
                FinalizeEncryption(x, y, k, n, mBytes, rRegister);
            }
        }
        finally
        {
            rRegister.Clear();
        }
    }

    private void EncryptFullBlocks(ReadOnlySpan<byte> x, Span<byte> y, ReadOnlySpan<byte> k, int count, Span<byte> rRegister)
    {
        Span<byte> blockBuffer = stackalloc byte[16];
        for (int i = 0; i < count; i++)
        {
            x.Slice(i * 16, 16).CopyTo(blockBuffer);
            BelTMath.GfBlock.Xor(blockBuffer, rRegister);

            _block.Encrypt(blockBuffer, k, y.Slice(i * 16, 16));
            y.Slice(i * 16, 16).CopyTo(rRegister);
        }
        blockBuffer.Clear();
    }
    private void FinalizeEncryption(ReadOnlySpan<byte> x, Span<byte> y, ReadOnlySpan<byte> k, int n, int mBytes, ReadOnlySpan<byte> rRegister)
    {
        int idxPrev = (n - 2) * 16;
        int idxLast = (n - 1) * 16;

        // Все промежуточные данные ТОЛЬКО на стеке
        Span<byte> blockXnMinus1 = stackalloc byte[16];
        Span<byte> blockXn = stackalloc byte[16];
        Span<byte> ynFull = stackalloc byte[16];
        Span<byte> ynMinus1 = stackalloc byte[16];

        try
        {
            // 1. Готовим Yn || r
            x.Slice(idxPrev, 16).CopyTo(blockXnMinus1);
            BelTMath.GfBlock.Xor(blockXnMinus1, rRegister);
            _block.Encrypt(blockXnMinus1, k, ynFull);

            // 2. Извлекаем r и Yn (пока в памяти стека)
            ReadOnlySpan<byte> r = ynFull[mBytes..];

            // 3. Готовим Yn-1
            x.Slice(idxLast, mBytes).CopyTo(blockXn);
            // XOR Xn ^ Yn (берём Yn из нашего стека ynFull)
            for (int j = 0; j < mBytes; j++)
                blockXn[j] ^= ynFull[j];

            // Склеиваем с r
            r.CopyTo(blockXn[mBytes..]);
            _block.Encrypt(blockXn, k, ynMinus1);

            // 4. И только теперь ОДНИМ движением переносим в выходной буфер
            // Это защищает от порчи данных при шифровании "в том же массиве"
            ynFull[..mBytes].CopyTo(y.Slice(idxLast, mBytes));
            ynMinus1.CopyTo(y.Slice(idxPrev, 16));
        }
        finally
        {
            // Принудительная зачистка стека
            blockXnMinus1.Clear();
            blockXn.Clear();
            ynFull.Clear();
            ynMinus1.Clear();
        }
    }
}
