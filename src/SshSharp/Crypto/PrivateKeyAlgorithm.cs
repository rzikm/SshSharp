using System.Numerics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using SshSharp.Utils;

namespace SshSharp.Crypto;

internal abstract class SshPublicKey
{
    public static SshPublicKey FromPrivateKeyFile(string privateKeyFile)
    {
        Regex PrivateKeyRegex = new Regex(@"^-+ *BEGIN (?<keyName>\w+( \w+)*) PRIVATE KEY *-+\r?\n((Proc-Type: 4,ENCRYPTED\r?\nDEK-Info: (?<cipherName>[A-Z0-9-]+),(?<salt>[A-F0-9]+)\r?\n\r?\n)|(Comment: ""?[^\r\n]*""?\r?\n))?(?<data>([a-zA-Z0-9/+=]{1,80}\r?\n)+)-+ *END \k<keyName> PRIVATE KEY *-+",
                                                                  RegexOptions.Compiled | RegexOptions.Multiline | RegexOptions.ExplicitCapture);

        var privateKeyText = System.IO.File.ReadAllText(privateKeyFile);

        var privateKeyMatch = PrivateKeyRegex.Match(privateKeyText);

        if (!privateKeyMatch.Success)
        {
            throw new Exception("Invalid private key file.");
        }

        var keyName = privateKeyMatch.Result("${keyName}");
        var cipherName = privateKeyMatch.Result("${cipherName}");
        var salt = privateKeyMatch.Result("${salt}");
        var data = privateKeyMatch.Result("${data}");

        SpanReader reader = new SpanReader(Convert.FromBase64String(data));

        var magic = "openssh-key-v1\0"u8;

        if (!reader.TryReadRawBytes(magic.Length, out var magicBytes) ||
            !magicBytes.SequenceEqual(magic))
        {
            throw new Exception("Invalid magic.");
        }

        if (!reader.TryReadStringAsSpan(out var cipherNameSpan) ||
            !reader.TryReadStringAsSpan(out var kdfNameSpan) ||
            !reader.TryReadStringAsSpan(out var kdfOptionsSpan) ||
            !reader.TryReadUInt32(out var numberOfKeys))
        {
            throw new Exception("Invalid format.");
        }

        if (!cipherNameSpan.SequenceEqual("none"u8))
        {
            throw new Exception("Did not expect cipher.");
        }

        if (!kdfNameSpan.SequenceEqual("none"u8))
        {
            throw new Exception("Did not expect kdf.");
        }

        if (kdfOptionsSpan.Length != 0)
        {
            throw new Exception("Did not expect kdf options.");
        }

        if (numberOfKeys != 1)
        {
            throw new Exception("Did not expect more than one key.");
        }

        if (!reader.TryReadStringAsSpan(out var keyTypeSpan) ||
            !reader.TryReadStringAsSpan(out var keyDataSpan))
        {
            throw new Exception("Invalid key format.");
        }

        if (keyDataSpan.Length % 8 != 0)
        {
            throw new Exception("Invalid key data length.");
        }

        reader = new SpanReader(keyDataSpan);

        if (!reader.TryReadUInt32(out var check1) ||
            !reader.TryReadUInt32(out var check2) ||
            check1 != check2)
        {
            throw new Exception("Invalid check bytes.");
        }

        if (!reader.TryReadString(out var keyType) || keyType != "ssh-rsa")
        {
            throw new Exception($"Invalid key type: {keyType}.");
        }

        if (!reader.TryReadStringAsSpan(out var modulus) ||
            !reader.TryReadStringAsSpan(out var exponent) ||
            !reader.TryReadStringAsSpan(out var d) ||
            !reader.TryReadStringAsSpan(out var inverseQ) ||
            !reader.TryReadStringAsSpan(out var p) ||
            !reader.TryReadStringAsSpan(out var q))
        {
            throw new Exception("Invalid key format.");
        }

        RSA rsa = RSA.Create();

        var BigIntSpanToArray = (ReadOnlySpan<byte> span) => span[0] == 0 ? span.Slice(1).ToArray() : span.ToArray();
        var primeExponent = (ReadOnlySpan<byte> privateExponent, ReadOnlySpan<byte> prime) =>
        {
            BigInteger p1 = new BigInteger(prime) - 1;
            var exp = new BigInteger(privateExponent) % p1;
            return exp.ToByteArray(isUnsigned: true, isBigEndian: true);
        };

        var parameters = new RSAParameters
        {
            Modulus = BigIntSpanToArray(modulus),
            Exponent = BigIntSpanToArray(exponent),
            D = BigIntSpanToArray(d),
            InverseQ = BigIntSpanToArray(inverseQ),
            P = BigIntSpanToArray(p),
            Q = BigIntSpanToArray(q),
        };

        parameters.DP = primeExponent(parameters.D, parameters.P);
        parameters.DQ = primeExponent(parameters.D, parameters.Q);

        rsa.ImportParameters(parameters);

        return new RsaPublicKey(rsa);
    }

    public abstract IEnumerable<IPublicKeyAuthAlgorithm> GetAlgorithms();
}

internal interface IPublicKeyAuthAlgorithm
{
    string AlgorithmName { get; }

    byte[] PublicKey { get; }

    byte[] GetSignature(ReadOnlySpan<byte> data);
}

internal class RsaPublicKey : SshPublicKey
{
    public override IEnumerable<IPublicKeyAuthAlgorithm> GetAlgorithms()
    {
        yield return new RsaPublicKeyAlgorithm(this, "ssh-rsa", HashAlgorithmName.SHA1);
        yield return new RsaPublicKeyAlgorithm(this, "rsa-sha2-256", HashAlgorithmName.SHA256);
        yield return new RsaPublicKeyAlgorithm(this, "rsa-sha2-512", HashAlgorithmName.SHA512);
    }

    private class RsaPublicKeyAlgorithm : IPublicKeyAuthAlgorithm
    {
        RsaPublicKey _rsa;

        public RsaPublicKeyAlgorithm(RsaPublicKey rsa, string algorithmName, HashAlgorithmName hashAlgorithmName)
        {
            _rsa = rsa;
            AlgorithmName = algorithmName;
            HashAlgorithmName = hashAlgorithmName;
        }

        public string AlgorithmName { get; }

        public byte[] PublicKey => _rsa.PublicKey;

        public HashAlgorithmName HashAlgorithmName { get; }

        public byte[] GetSignature(ReadOnlySpan<byte> data)
        {
            return _rsa.GetSignatureBlob(data, AlgorithmName, HashAlgorithmName);
        }
    }

    RSA _rsa;

    public byte[] PublicKey { get; }

    public RsaPublicKey(RSA rsa)
    {
        _rsa = rsa;
        PublicKey = GetPublicKeyBlob();
    }

    private byte[] GetPublicKeyBlob()
    {
        var parameters = _rsa.ExportParameters(false);

        Span<byte> buffer = new byte[1024];

        SpanWriter writer = new SpanWriter(buffer);

        writer.WriteString("ssh-rsa");
        writer.WriteBigInt(parameters.Exponent);
        writer.WriteBigInt(parameters.Modulus);

        return buffer.Slice(0, buffer.Length - writer.RemainingBytes).ToArray();
    }

    public byte[] GetSignatureBlob(ReadOnlySpan<byte> data, string algorithmName, HashAlgorithmName hashAlgorithmName)
    {
        Span<byte> signature = stackalloc byte[1024];
        SpanWriter writer = new(signature);
        writer.WriteString(algorithmName);
        writer.WriteString(_rsa.SignData(data, hashAlgorithmName, RSASignaturePadding.Pkcs1));
        return signature.Slice(0, signature.Length - writer.RemainingBytes).ToArray();
    }
}