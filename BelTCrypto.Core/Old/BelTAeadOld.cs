using BelTCrypto.Core.Interfaces.Old;

namespace BelTCrypto.Core.Old;

internal abstract class BelTAeadOld(IBelTBlockOld block) : IBelTAeadOld
{
    protected readonly IBelTBlockOld _block = block ?? throw new ArgumentNullException(nameof(block));
    protected bool _isDisposed;

    public abstract (byte[] CipherText, byte[] Tag) Protect(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> iv);

    public abstract byte[] Unprotect(
        ReadOnlySpan<byte> cipherText,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> tag);

    public void Dispose()
    {
        if (_isDisposed) return;
        _block?.Dispose();
        _isDisposed = true;
    }
}
