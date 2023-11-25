using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

struct UserAuthRequestHeader : IPacketPayload<UserAuthRequestHeader>
{
    public int WireLength => GetWireLength();

    public string Username { get; set; }
    public string ServiceName { get; set; }

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

    public static bool TryRead(ref SpanReader reader, out UserAuthRequestHeader header)
    {
        header = default;

        if (!reader.TryReadString(out var username) ||
            !reader.TryReadString(out var serviceName))
        {
            return false;
        }

        header = new UserAuthRequestHeader(username, serviceName);
        return true;
    }

    public static void Write(ref SpanWriter writer, in UserAuthRequestHeader packet)
    {
        writer.WriteByte((byte)MessageId);

        writer.WriteString(packet.Username);
        writer.WriteString(packet.ServiceName);
    }
}