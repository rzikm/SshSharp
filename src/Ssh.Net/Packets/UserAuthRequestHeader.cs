using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

struct UserAuthRequestHeader : IPacketPayload<UserAuthRequestHeader>
{
    public string Username { get; }
    public string ServiceName { get; }
    public string MethodName { get; }

    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_USERAUTH_REQUEST;

    private int GetWireLength()
    {
        int length = 1;

        length += DataHelper.GetStringWireLength(Username);
        length += DataHelper.GetStringWireLength(ServiceName);
        length += DataHelper.GetStringWireLength(MethodName);

        return length;
    }

    public UserAuthRequestHeader(string username, string serviceName, string methodName)
    {
        Username = username;
        ServiceName = serviceName;
        MethodName = methodName;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out UserAuthRequestHeader header, out int consumed)
    {
        consumed = 0;
        header = default;

        SpanReader reader = new(buffer);

        if (!reader.TryReadString(out var username) ||
            !reader.TryReadString(out var serviceName) ||
            !reader.TryReadString(out var methodName))
        {
            consumed = buffer.Length - reader.RemainingBytes;
            return false;
        }

        consumed = buffer.Length - reader.RemainingBytes;
        header = new UserAuthRequestHeader(username, serviceName, methodName);
        return true;
    }

    static int IPacketPayload<UserAuthRequestHeader>.Write(Span<byte> destination, in UserAuthRequestHeader packet)
    {
        SpanWriter writer = new(destination);

        writer.WriteByte((byte)MessageId.SSH_MSG_USERAUTH_REQUEST);
        writer.WriteString(packet.Username);
        writer.WriteString(packet.ServiceName);
        writer.WriteString(packet.MethodName);

        return destination.Length - writer.RemainingBytes;
    }
}