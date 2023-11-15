using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal static class KeyGenerationHelpers
{
    internal static byte[] DeriveSessionKey(ReadOnlySpan<byte> sharedKey, ReadOnlySpan<byte> exchangeHash, char c, ReadOnlySpan<byte> sessionId, KeyExchange keyExchange, int keyLength)
    {
        //   K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
        //   K2 = HASH(K || H || K1)
        //   K3 = HASH(K || H || K1 || K2)
        //   ...
        //   key = K1 || K2 || K3 || ...

        Span<byte> srcSpan = stackalloc byte[sharedKey.Length + 5 + exchangeHash.Length + Math.Max(1 + sessionId.Length, keyLength + (keyExchange.HashAlgorithm.HashSize / 8))];
        var writer = new SpanWriter(srcSpan);
        writer.WriteBigInt(sharedKey);
        writer.WriteRawData(exchangeHash);

        // offset where the final key will start
        var offset = srcSpan.Length - writer.RemainingBytes;

        writer.WriteByte((byte)c);
        writer.WriteRawData(sessionId);

        var hashedSpan = srcSpan.Slice(0, srcSpan.Length - writer.RemainingBytes);

        var currentKeyLength = 0;

        Span<byte> tmpSpan = stackalloc byte[keyExchange.HashAlgorithm.HashSize / 8];
        do
        {
            keyExchange.HashAlgorithm.TryComputeHash(hashedSpan, srcSpan.Slice(offset + currentKeyLength), out var written);
            currentKeyLength += written;
        } while (currentKeyLength < keyLength);

        return srcSpan.Slice(offset, keyLength).ToArray();
    }
}