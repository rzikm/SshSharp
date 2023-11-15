using System.Linq;
using System.Security.Cryptography;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal class KeyExchangeCurve25519Sha256 : KeyExchangeECDH, IDisposable
{
    public KeyExchangeCurve25519Sha256(byte[]? privateKey = null) : base("curve25519-sha256", ECCurves.Curve25519, SHA256.Create(), privateKey)
    {
    }

    protected override byte[] GetPublicEphemeralKey(ECDiffieHellmanPublicKey publicKey)
    {
        var parameters = publicKey.ExportParameters();
        return parameters.Q.X!;
    }

    protected override ECPoint GetECPointFromPublicKey(byte[] otherPartyPublicKey)
    {
        return new ECPoint
        {
            X = otherPartyPublicKey,
            Y = new byte[32]
        };
    }
}