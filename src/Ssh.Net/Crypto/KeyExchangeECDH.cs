using System.Security.Cryptography;

namespace Ssh.Net.Crypto;

internal class KeyExchangeECDH : KeyExchange, IDisposable
{
    private readonly ECDiffieHellman _ecdh;

    private byte[]? _secret;

    public ECCurve Curve { get; }

    public override byte[] EphemeralPublicKey { get; }

    public override byte[]? SharedSecret => _secret;

    public KeyExchangeECDH(string name, ECCurve curve, byte[]? privateKey = null) : base(name)
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

    public override void DeriveSharedSecret(byte[] otherPublicKey)
    {
        using var otherEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = Curve,
            Q = GetECPointFromPublicKey(otherPublicKey)
        });
        _secret = _ecdh.DeriveRawSecretAgreement(otherEcdh.PublicKey);
    }

    protected override byte[] Hash(ReadOnlySpan<byte> data)
    {
        // TODO: select hash based on the key exchange algorithm
        return SHA256.HashData(data);
    }

    public void Dispose()
    {
        _ecdh.Dispose();
    }
}