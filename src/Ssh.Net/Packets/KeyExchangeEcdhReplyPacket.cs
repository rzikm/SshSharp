using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct KeyExchangeEcdhReplyPacket : IPacketPayload<KeyExchangeEcdhReplyPacket>
{
    public int WireLength => GetWireLength();

    public byte[] HostKey { get; set; }
    public byte[] ServerEphemeralPublicKey { get; set; }
    public byte[] ExchangeHashSignature { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_KEXDH_REPLY;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(HostKey);
        length += DataHelper.GetStringWireLength(ServerEphemeralPublicKey);
        length += DataHelper.GetStringWireLength(ExchangeHashSignature);

        return length;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out KeyExchangeEcdhReplyPacket payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadStringAsSpan(out var hostKey) ||
            !reader.TryReadStringAsSpan(out var serverEphemeralPublicKey) ||
            !reader.TryReadStringAsSpan(out var exchangeHashSignature))
        {
            payload = default;
            consumed = buffer.Length - reader.RemainingBytes;
            return false;
        }

        payload = new KeyExchangeEcdhReplyPacket()
        {
            HostKey = hostKey.ToArray(),
            ServerEphemeralPublicKey = serverEphemeralPublicKey.ToArray(),
            ExchangeHashSignature = exchangeHashSignature.ToArray()
        };
        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in KeyExchangeEcdhReplyPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        writer.WriteByte((byte)MessageId.SSH_MSG_KEXDH_REPLY);
        writer.WriteString(packet.HostKey);
        writer.WriteString(packet.ServerEphemeralPublicKey);
        writer.WriteString(packet.ExchangeHashSignature);

        return destination.Length - writer.RemainingBytes;
    }
}