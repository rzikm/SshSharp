using System.Linq;
using System.Security.Cryptography;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal class KeyExchangeCurve25519Sha256 : IDisposable
{
    private readonly ECDiffieHellman _ecdh;

    public byte[] PublicKey { get; private set; }

    public byte[] SharedSecret { get; private set; } = null!;

    public KeyExchangeCurve25519Sha256()
    {
        _ecdh = ECDiffieHellman.Create();
        _ecdh.GenerateKey(ECCurves.Curve25519);

        var parameters = _ecdh.PublicKey.ExportParameters();
        PublicKey = parameters.Q.X!;
    }

    public KeyExchangeCurve25519Sha256(byte[] privateKey)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurves.Curve25519,
            D = privateKey
        };

        _ecdh = ECDiffieHellman.Create(parameters);
        parameters = _ecdh.PublicKey.ExportParameters();

        PublicKey = parameters.Q.X!;
    }

    public byte[] DeriveSharedSecret(byte[] otherPublicKey)
    {
        var otherParams = new ECParameters
        {
            Curve = ECCurves.Curve25519,
            Q = {
                X = otherPublicKey,
                Y = new byte[32]
            }
        };

        using var otherEcdh = ECDiffieHellman.Create(otherParams);
        SharedSecret = _ecdh.DeriveRawSecretAgreement(otherEcdh.PublicKey);
        return SharedSecret;
    }

    public bool VerifyExchangeSignature(byte[] serverVersion, byte[] clientVersion, KeyExchangeInitPacket clientInit, KeyExchangeInitPacket serverInit, KeyExchangeEcdhReplyPacket kexReply)
    {
        System.Console.WriteLine("Verifying exchange signature");

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
        writer.WriteString(PublicKey);
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

        return true;
    }

    public void Dispose()
    {
        _ecdh.Dispose();
    }

    byte[] DecodeString(string s)
    {
        return s.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();
    }
}