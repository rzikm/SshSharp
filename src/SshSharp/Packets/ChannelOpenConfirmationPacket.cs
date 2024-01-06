using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelOpenConfirmationPacket : IPacketPayload<ChannelOpenConfirmationPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;

    public int RecipientChannel { get; set; }
    public int SenderChannel { get; set; }
    public int InitialWindowSize { get; set; }
    public int MaximumPacketSize { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += 4; // senderChannel
        length += 4; // initialWindowSize
        length += 4; // maximumPacketSize

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelOpenConfirmationPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadUInt32(out var senderChannel) ||
            !reader.TryReadUInt32(out var initialWindowSize) ||
            !reader.TryReadUInt32(out var maximumPacketSize))
        {
            payload = default;
            return false;
        }

        payload = new ChannelOpenConfirmationPacket()
        {
            RecipientChannel = (int)recipientChannel,
            SenderChannel = (int)senderChannel,
            InitialWindowSize = (int)initialWindowSize,
            MaximumPacketSize = (int)maximumPacketSize,
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelOpenConfirmationPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteUInt32((uint)payload.SenderChannel);
        writer.WriteUInt32((uint)payload.InitialWindowSize);
        writer.WriteUInt32((uint)payload.MaximumPacketSize);
    }
}