using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct UserauthPublicKeyData : IUserauthMethod<UserauthPublicKeyData>
{
    public int WireLength => GetWireLength();

    public string AlgorithmName { get; set; }
    public byte[] PublicKey { get; set; }
    public byte[]? Signature { get; set; }

    public static string Name => "publickey";

    private int GetWireLength()
    {
        var length = DataHelper.GetStringWireLength(Name);

        length += 1; // has signature
        length += DataHelper.GetStringWireLength(AlgorithmName);
        length += DataHelper.GetStringWireLength(PublicKey);

        if (Signature != null)
        {
            length += DataHelper.GetStringWireLength(Signature);
        }

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out UserauthPublicKeyData payload)
    {
        ReadOnlySpan<byte> signature = default;
        if (!reader.TryReadBoolean(out var hasSignature) ||
            !reader.TryReadString(out var algorithmName) ||
            !reader.TryReadStringAsSpan(out var publicKey) ||
            (hasSignature && !reader.TryReadStringAsSpan(out signature)))
        {
            payload = default;
            return false;
        }

        payload = new UserauthPublicKeyData
        {
            AlgorithmName = algorithmName,
            PublicKey = publicKey.ToArray(),
            Signature = hasSignature ? signature.ToArray() : null
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in UserauthPublicKeyData payload)
    {
        writer.WriteString(Name);

        writer.WriteBoolean(payload.Signature != null);
        writer.WriteString(payload.AlgorithmName);
        writer.WriteString(payload.PublicKey);

        if (payload.Signature != null)
        {
            writer.WriteString(payload.Signature);
        }
    }
}