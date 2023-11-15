using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

struct UserAuthRequestHeader : IPacketPayload<UserAuthRequestHeader>
{
    public string Username { get; set; }
    public string ServiceName { get; set; }

    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_USERAUTH_REQUEST;

    private int GetWireLength()
    {
        int length = 1;

        length += DataHelper.GetStringWireLength(Username);
        length += DataHelper.GetStringWireLength(ServiceName);

        return length;
    }

    public UserAuthRequestHeader(string username, string serviceName)
    {
        Username = username;
        ServiceName = serviceName;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out UserAuthRequestHeader header, out int consumed)
    {
        header = default;

        SpanReader reader = new(buffer);

        if (!reader.TryReadString(out var username) ||
            !reader.TryReadString(out var serviceName))
        {
            consumed = buffer.Length - reader.RemainingBytes;
            return false;
        }

        consumed = buffer.Length - reader.RemainingBytes;
        header = new UserAuthRequestHeader(username, serviceName);
        return true;
    }

    public static int Write(Span<byte> destination, in UserAuthRequestHeader packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);
        writer.WriteByte((byte)MessageId);

        writer.WriteString(packet.Username);
        writer.WriteString(packet.ServiceName);

        return destination.Length - writer.RemainingBytes;
    }
}