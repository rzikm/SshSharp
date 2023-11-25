using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ServiceRequestPacket : IPacketPayload<ServiceRequestPacket>
{
    public int WireLength => GetWireLength();

    public string ServiceName { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_SERVICE_REQUEST;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(ServiceName);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ServiceRequestPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadString(out var serviceName))
        {
            payload = default;
            return false;
        }

        payload = new ServiceRequestPacket
        {
            ServiceName = serviceName
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in ServiceRequestPacket payload)
    {
        writer.WriteByte((byte)MessageId.SSH_MSG_SERVICE_REQUEST);
        writer.WriteString(payload.ServiceName);
    }
}
