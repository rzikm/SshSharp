using System.Security.Cryptography;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal abstract class KeyExchange
{
    public abstract byte[] EphemeralPublicKey { get; }

    public abstract byte[]? SharedSecret { get; }

    protected internal abstract void DeriveSharedSecret(byte[] otherPublicKey);

    public static KeyExchange Create(string keyExchangeAlgorithm)
    {
        return keyExchangeAlgorithm switch
        {
            "curve25519-sha256" => new KeyExchangeCurve25519Sha256(),
            "ecdh-sha2-nistp256" => new KeyExchangeECDH(),
            _ => throw new Exception($"Unsupported key exchange algorithm: {keyExchangeAlgorithm}")
        };
    }

    public bool VerifyExchangeSignature(byte[] serverVersion, byte[] clientVersion, in KeyExchangeInitPacket clientInit, in KeyExchangeInitPacket serverInit, in KeyExchangeEcdhReplyPacket kexReply)
    {
        DeriveSharedSecret(kexReply.ServerEphemeralPublicKey);

        using var rsa = RSA.Create();

        SpanReader reader = new SpanReader(kexReply.HostKey);
        if (!reader.TryReadString(out var hostKeyAlgorithm) ||
            !reader.TryReadStringAsSpan(out var exponent) ||
            !reader.TryReadStringAsSpan(out var n))
        {
            throw new Exception("Invalid host key");
        }

        Console.WriteLine($"Host key algorithm: {hostKeyAlgorithm}");

        RSAParameters rsaParameters = new RSAParameters
        {
            Exponent = exponent.ToArray(),
            Modulus = n.ToArray()
        };

        rsa.ImportParameters(rsaParameters);

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

        reader = new SpanReader(kexReply.ExchangeHashSignature);
        if (!reader.TryReadString(out var signatureType) ||
            !reader.TryReadStringAsSpan(out var signature))
        {
            throw new Exception("Invalid signature");
        }

        System.Console.WriteLine($"Signature type: {signatureType}");

        // hash of the above data (as per key exchange curve25519-sha256)
        var hash = SHA256.HashData(buffer);

        var hash512 = SHA512.HashData(hash);

        // Hash and verify again against hash from host key (rsa-sha2-512)
        var result = rsa.VerifyHash(hash512, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        System.Console.WriteLine($"Signature verified: {result}");
        return result;
    }
}