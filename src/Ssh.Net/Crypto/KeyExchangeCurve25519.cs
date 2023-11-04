using System.Linq;
using System.Security.Cryptography;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal class KeyExchangeCurve25519Sha256 : KeyExchange, IDisposable
{
    private readonly ECDiffieHellman _ecdh;
    private byte[]? _secret;

    public override byte[] EphemeralPublicKey { get; }

    public override byte[]? SharedSecret => _secret;

    public KeyExchangeCurve25519Sha256()
    {
        _ecdh = ECDiffieHellman.Create();
        _ecdh.GenerateKey(ECCurves.Curve25519);

        var parameters = _ecdh.PublicKey.ExportParameters();
        EphemeralPublicKey = parameters.Q.X!;
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

        EphemeralPublicKey = parameters.Q.X!;
    }

    protected internal override void DeriveSharedSecret(byte[] otherPublicKey)
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
        _secret = _ecdh.DeriveRawSecretAgreement(otherEcdh.PublicKey);
    }

    public void Dispose()
    {
        _ecdh.Dispose();
    }
}