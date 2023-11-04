using Ssh.Net.Utils;

namespace Ssh.Net;

struct UserAuthRequestHeader
{
    public string Username { get; }
    public string ServiceName { get; }
    public string MethodName { get; }

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
}