namespace BelTCrypto.Core.Interfaces.Old;

public interface IBelTAeadOld : IDisposable
{
    (byte[] CipherText, byte[] Tag) Protect(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> iv);
    byte[] Unprotect(ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> tag);
}
