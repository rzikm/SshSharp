using System.Security.Cryptography;
using SshSharp.Packets;
using SshSharp.Utils;

namespace SshSharp.Crypto;

internal class HostKeyRsa : HostKeyAlgorithm
{
    private readonly RSA _rsa;

    public override string Name => "ssh-rsa";

    public HostKeyRsa(RSA rsa)
    {
        _rsa = rsa;
    }

    public static HostKeyRsa CreateFromSerializedParameters(SpanReader reader)
    {
        if (!reader.TryReadStringAsSpan(out var exponent) ||
            !reader.TryReadStringAsSpan(out var n))
        {
            throw new Exception("Invalid host key");
        }

        RSAParameters rsaParameters = new RSAParameters
        {
            Exponent = exponent.ToArray(),
            Modulus = n.ToArray()
        };

        var rsa = RSA.Create();
        rsa.ImportParameters(rsaParameters);

        return new HostKeyRsa(rsa);
    }

    public override bool VerifyExchangeHashSignature(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> exchaneSignature)
    {
        var reader = new SpanReader(exchaneSignature);
        if (!reader.TryReadString(out var signatureType) ||
            !reader.TryReadStringAsSpan(out var signature))
        {
            throw new Exception("Invalid signature");
        }

        var hashAlgorithmName = signatureType switch
        {
            "ssh-rsa" => HashAlgorithmName.SHA1,
            "rsa-sha2-256" => HashAlgorithmName.SHA256,
            "rsa-sha2-512" => HashAlgorithmName.SHA512,
            _ => throw new Exception($"Unsupported signature type: {signatureType}")
        };

        // Hash again and verify again against the host key
        var result = _rsa.VerifyData(hash, signature, hashAlgorithmName, RSASignaturePadding.Pkcs1);

        return result;
    }
}