using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelOpenFailurePacket : IPacketPayload<ChannelOpenFailurePacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_CHANNEL_OPEN_FAILURE;

    public int RecipientChannel { get; set; }
    public int ReasonCode { get; set; }
    public string Description { get; set; }
    public string LanguageTag { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // recipientChannel
        length += 4; // reasonCode
        length += DataHelper.GetStringWireLength(Description);
        length += DataHelper.GetStringWireLength(LanguageTag);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelOpenFailurePacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var recipientChannel) ||
            !reader.TryReadUInt32(out var reasonCode) ||
            !reader.TryReadString(out var description) ||
            !reader.TryReadString(out var languageTag))
        {
            payload = default;
            return false;
        }

        payload = new ChannelOpenFailurePacket()
        {
            RecipientChannel = (int)recipientChannel,
            ReasonCode = (int)reasonCode,
            Description = description,
            LanguageTag = languageTag,
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelOpenFailurePacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteUInt32((uint)payload.RecipientChannel);
        writer.WriteUInt32((uint)payload.ReasonCode);
        writer.WriteString(payload.Description);
        writer.WriteString(payload.LanguageTag);
    }
}