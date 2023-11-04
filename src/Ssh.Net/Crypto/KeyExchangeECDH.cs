using System.Security.Cryptography;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal class KeyExchangeECDH : KeyExchange, IDisposable
{
    private readonly ECDiffieHellman _ecdh;

    private byte[]? _secret;

    public override byte[] EphemeralPublicKey { get; }

    public override byte[]? SharedSecret => _secret;

    public KeyExchangeECDH()
    {
        _ecdh = ECDiffieHellman.Create();
        _ecdh.GenerateKey(ECCurve.NamedCurves.nistP256);

        var parameters = _ecdh.PublicKey.ExportParameters();
        EphemeralPublicKey = new byte[] { 0x04 }.Concat(parameters.Q.X!).Concat(parameters.Q.Y!).ToArray();
    }

    protected internal override void DeriveSharedSecret(byte[] otherPublicKey)
    {
        var otherParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = {
                X = otherPublicKey[1..33],
                Y = otherPublicKey[33..]
            }
        };

        using var otherEcdh = ECDiffieHellman.Create(otherParams);
        _secret = _ecdh.DeriveRawSecretAgreement(otherEcdh.PublicKey);
    }
    public void Dispose()
    {
        _ecdh.Dispose();
    }
}