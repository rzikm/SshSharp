using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelWindowAdjustPacket : IPacketPayload<ChannelWindowAdjustPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST;

    public int RecipientChannel { get; set; }

    public int BytesToAdd { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += 4; // bytesToAdd

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelWindowAdjustPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadUInt32(out var bytesToAdd))
        {
            payload = default;
            return false;
        }

        payload = new ChannelWindowAdjustPacket()
        {
            RecipientChannel = (int)recipientChannel,
            BytesToAdd = (int)bytesToAdd
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelWindowAdjustPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteUInt32((uint)payload.BytesToAdd);
    }
}