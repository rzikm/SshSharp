using System.Security.Cryptography;

namespace Ssh.Net.Crypto;

internal class KeyExchangeECDH : KeyExchange, IDisposable
{
    private readonly ECDiffieHellman _ecdh;

    public ECCurve Curve { get; }

    public override byte[] EphemeralPublicKey { get; }

    public KeyExchangeECDH(string name, ECCurve curve, HashAlgorithm hashAlgorithm, byte[]? privateKey = null) : base(name, hashAlgorithm)
    {
        Curve = curve;

        if (privateKey != null)
        {
            _ecdh = ECDiffieHellman.Create(new ECParameters
            {
                Curve = curve,
                D = privateKey
            });
        }
        else
        {
            _ecdh = ECDiffieHellman.Create(curve);
        }

        EphemeralPublicKey = GetPublicEphemeralKey(_ecdh.PublicKey);
    }

    protected virtual byte[] GetPublicEphemeralKey(ECDiffieHellmanPublicKey publicKey)
    {
        var parameters = publicKey.ExportParameters();
        return new byte[] { 0x04 }.Concat(parameters.Q.X!).Concat(parameters.Q.Y!).ToArray();
    }

    protected virtual ECPoint GetECPointFromPublicKey(byte[] otherPartyPublicKey)
    {
        return new ECPoint
        {
            X = otherPartyPublicKey[1..33],
            Y = otherPartyPublicKey[33..]
        };
    }

    protected override byte[] DeriveSharedSecretCore(byte[] otherPublicKey)
    {
        using var otherEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = Curve,
            Q = GetECPointFromPublicKey(otherPublicKey)
        });

        return _ecdh.DeriveRawSecretAgreement(otherEcdh.PublicKey)!;
    }

    public void Dispose()
    {
        _ecdh.Dispose();
    }
}