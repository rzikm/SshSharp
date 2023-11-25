using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct DisconnectPacket : IPacketPayload<DisconnectPacket>
{
    public uint ReasonCode { get; set; }
    public string Description { get; set; }
    public string LanguageTag { get; set; }

    public int WireLength => GetWireLength();

    public static MessageId MessageId => throw new NotImplementedException();

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // ReasonCode
        length += DataHelper.GetStringWireLength(Description);
        length += DataHelper.GetStringWireLength(LanguageTag);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out DisconnectPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadUInt32(out var reasonCode) ||
            !reader.TryReadString(out var description) ||
            !reader.TryReadString(out var languageTag))
        {
            payload = default;
            return false;
        }

        payload = new DisconnectPacket()
        {
            ReasonCode = reasonCode,
            Description = description,
            LanguageTag = languageTag
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in DisconnectPacket payload)
    {
        writer.WriteByte((byte)MessageId.SSH_MSG_DISCONNECT);
        writer.WriteUInt32(payload.ReasonCode);
        writer.WriteString(payload.Description);
        writer.WriteString(payload.LanguageTag);
    }
}