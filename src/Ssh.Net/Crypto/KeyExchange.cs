using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal abstract class KeyExchange
{
    public string Name { get; }

    public abstract byte[] EphemeralPublicKey { get; }

    public byte[]? SharedSecret { get; private set; }

    protected abstract byte[] DeriveSharedSecretCore(byte[] otherPublicKey);

    [MemberNotNull(nameof(SharedSecret))]
    public void DeriveSharedSecret(byte[] otherPublicKey)
    {
        SharedSecret = DeriveSharedSecretCore(otherPublicKey);
    }

    public KeyExchange(string name)
    {
        Name = name;
    }

    public static KeyExchange Create(string keyExchangeAlgorithm)
    {
        return keyExchangeAlgorithm switch
        {
            "curve25519-sha256" => new KeyExchangeCurve25519Sha256(),
            "ecdh-sha2-nistp256" => new KeyExchangeECDH(keyExchangeAlgorithm, ECCurve.NamedCurves.nistP256),
            _ => throw new Exception($"Unsupported key exchange algorithm: {keyExchangeAlgorithm}")
        };
    }

    public byte[] GetExchangeHash(byte[] serverVersion, byte[] clientVersion, in KeyExchangeInitPacket clientInit, in KeyExchangeInitPacket serverInit, in KeyExchangeEcdhReplyPacket kexReply)
    {
        DeriveSharedSecret(kexReply.ServerEphemeralPublicKey);

        Span<byte> buffer = stackalloc byte[4 * 1024];

        SpanWriter writer = new SpanWriter(buffer);

        writer.WriteString(clientVersion);
        writer.WriteString(serverVersion);
        writer.WritePayloadAsString(clientInit);
        writer.WritePayloadAsString(serverInit);
        writer.WriteString(kexReply.HostKey);
        writer.WriteString(EphemeralPublicKey);
        writer.WriteString(kexReply.ServerEphemeralPublicKey);
        writer.WriteBigInt(SharedSecret);
        buffer = buffer.Slice(0, buffer.Length - writer.RemainingBytes);

        return Hash(buffer);
    }

    public abstract byte[] Hash(ReadOnlySpan<byte> data);
}