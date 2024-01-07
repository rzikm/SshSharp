using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelExtendedDataPacket : IPacketPayload<ChannelExtendedDataPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA;

    public int RecipientChannel { get; set; }
    public int DataTypeCode { get; set; }
    public byte[] Data { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += 4; // dataTypeCode
        length += DataHelper.GetStringWireLength(Data);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelExtendedDataPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadUInt32(out var dataTypeCode) ||
            !reader.TryReadStringAsSpan(out var data))
        {
            payload = default;
            return false;
        }

        payload = new ChannelExtendedDataPacket()
        {
            RecipientChannel = (int)recipientChannel,
            DataTypeCode = (int)dataTypeCode,
            Data = data.ToArray()
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelExtendedDataPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteUInt32((uint)payload.DataTypeCode);
        writer.WriteString(payload.Data);
    }
}