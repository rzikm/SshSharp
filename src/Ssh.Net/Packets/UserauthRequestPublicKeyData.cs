using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

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

    public static bool TryRead(ReadOnlySpan<byte> buffer, out UserauthPublicKeyData payload, out int consumed)
    {
        var reader = new SpanReader(buffer);

        if (!reader.TryReadString(out var name) || name != Name)
        {
            throw new Exception($"Unexpected auth method: {name}.");
        }

        ReadOnlySpan<byte> signature = default;

        if (!reader.TryReadBoolean(out var hasSignature) ||
            !reader.TryReadString(out var algorithmName) ||
            !reader.TryReadStringAsSpan(out var publicKey) ||
            (hasSignature && !reader.TryReadStringAsSpan(out signature)))
        {
            consumed = buffer.Length - reader.RemainingBytes;
            payload = default;
            return false;
        }

        payload = new UserauthPublicKeyData
        {
            AlgorithmName = algorithmName,
            PublicKey = publicKey.ToArray(),
            Signature = hasSignature ? signature.ToArray() : null
        };

        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in UserauthPublicKeyData packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);
        writer.WriteString(Name);

        writer.WriteBoolean(packet.Signature != null);
        writer.WriteString(packet.AlgorithmName);
        writer.WriteString(packet.PublicKey);

        if (packet.Signature != null)
        {
            writer.WriteString(packet.Signature);
        }

        return destination.Length - writer.RemainingBytes;
    }
}