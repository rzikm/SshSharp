using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelDataPacket : IPacketPayload<ChannelDataPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_DATA;

    public int RecipientChannel { get; set; }

    public byte[] Data { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += DataHelper.GetStringWireLength(Data);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelDataPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadStringAsSpan(out var data))
        {
            payload = default;
            return false;
        }

        payload = new ChannelDataPacket()
        {
            RecipientChannel = (int)recipientChannel,
            Data = data.ToArray()
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelDataPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteString(payload.Data);
    }
}