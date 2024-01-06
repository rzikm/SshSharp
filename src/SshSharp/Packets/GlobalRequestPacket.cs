using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct GlobalRequestPacket : IPacketPayload<GlobalRequestPacket>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_GLOBAL_REQUEST;

    public string RequestName { get; set; }
    public bool WantReply { get; set; }

    private int GetWireLength()
    {
        var length = 1;

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out GlobalRequestPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadString(out var requestName) ||
            !reader.TryReadBoolean(out var wantReply))
        {
            payload = default;
            return false;
        }

        payload = new GlobalRequestPacket()
        {
            RequestName = requestName,
            WantReply = wantReply,
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in GlobalRequestPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteString(payload.RequestName);
        writer.WriteBoolean(payload.WantReply);
    }
}