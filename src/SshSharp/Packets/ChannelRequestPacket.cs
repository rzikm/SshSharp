using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelRequestHeader : IPacketPayload<ChannelRequestHeader>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_REQUEST;

    public int RecipientChannel { get; set; }
    public string RequestType { get; set; }
    public bool WantReply { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += DataHelper.GetStringWireLength(RequestType);
        length += 1; // wantReply

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelRequestHeader payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadString(out var requestType) ||
            !reader.TryReadByte(out var wantReply))
        {
            payload = default;
            return false;
        }

        payload = new ChannelRequestHeader()
        {
            RecipientChannel = (int)recipientChannel,
            RequestType = requestType,
            WantReply = wantReply == 1,
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelRequestHeader payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteString(payload.RequestType);
        writer.WriteBoolean(payload.WantReply);
    }
}