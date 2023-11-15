using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

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

    public static bool TryRead(ReadOnlySpan<byte> buffer, out ServiceRequestPacket payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadString(out var serviceName))
        {
            consumed = buffer.Length - reader.RemainingBytes;
            payload = default;
            return false;
        }

        payload = new ServiceRequestPacket
        {
            ServiceName = serviceName
        };

        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in ServiceRequestPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        writer.WriteByte((byte)MessageId.SSH_MSG_SERVICE_REQUEST);
        writer.WriteString(packet.ServiceName);

        return destination.Length - writer.RemainingBytes;
    }
}
