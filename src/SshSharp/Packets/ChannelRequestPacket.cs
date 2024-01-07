using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelRequestPacket : IPacketPayload<ChannelRequestPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_REQUEST;

    public int RecipientChannel { get; set; }
    public string RequestType { get; set; }
    public bool WantReply { get; set; }
    public string? Arg { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += DataHelper.GetStringWireLength(RequestType);
        length += 1; // wantReply
        if (Arg != null)
        {
            length += DataHelper.GetStringWireLength(Arg);
        }

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelRequestPacket payload)
    {
        string? arg = null;

        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadString(out var requestType) ||
            !reader.TryReadByte(out var wantReply) ||
            (reader.RemainingBytes > 0 && !reader.TryReadString(out arg)))
        {
            payload = default;
            return false;
        }

        payload = new ChannelRequestPacket()
        {
            RecipientChannel = (int)recipientChannel,
            RequestType = requestType,
            WantReply = wantReply == 1,
            Arg = arg
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelRequestPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteString(payload.RequestType);
        writer.WriteBoolean(payload.WantReply);
        if (payload.Arg != null)
        {
            writer.WriteString(payload.Arg);
        }
    }
}