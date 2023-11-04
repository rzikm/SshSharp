using System.Security.Cryptography;

namespace Ssh.Net.Crypto;

internal class KeyExchangeCurve25519 : IDisposable
{
    private readonly ECDiffieHellman _ecdh;

    public byte[] PublicKey { get; private set; }

    public KeyExchangeCurve25519()
    {
        _ecdh = ECDiffieHellman.Create();
        _ecdh.GenerateKey(ECCurves.Curve25519);

        var parameters = _ecdh.PublicKey.ExportParameters();
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
        return _ecdh.DeriveKeyFromHash(otherEcdh.PublicKey, HashAlgorithmName.SHA256);
    }

    public void Dispose()
    {
        _ecdh.Dispose();
    }
}