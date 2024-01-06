using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct SessionOpenPacket : IPacketPayload<SessionOpenPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_OPEN;

    public static string ChannelType => "session";

    public int SenderChannel { get; set; }
    public int InitialWindowSize { get; set; }
    public int MaximumPacketSize { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(ChannelType);
        length += 4; // senderChannel
        length += 4; // initialWindowSize
        length += 4; // maximumPacketSize

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out SessionOpenPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadString(out var channelType) || channelType != ChannelType ||
            !reader.TryReadUInt32(out var senderChannel) ||
            !reader.TryReadUInt32(out var initialWindowSize) ||
            !reader.TryReadUInt32(out var maximumPacketSize))
        {
            payload = default;
            return false;
        }

        payload = new SessionOpenPacket()
        {
            SenderChannel = (int)senderChannel,
            InitialWindowSize = (int)initialWindowSize,
            MaximumPacketSize = (int)maximumPacketSize,
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in SessionOpenPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteString(ChannelType);
        writer.WriteUInt32((uint)payload.SenderChannel);
        writer.WriteUInt32((uint)payload.InitialWindowSize);
        writer.WriteUInt32((uint)payload.MaximumPacketSize);
    }
}
