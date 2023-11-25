using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct UserauthFailurePacket : IPacketPayload<UserauthFailurePacket>
{
    public int WireLength => GetWireLength();

    public List<string> AuthThatCanContinue { get; set; }
    public bool PartialSuccess { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_USERAUTH_FAILURE;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringListWireLength(AuthThatCanContinue);
        length += 1; // PartialSuccess

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out UserauthFailurePacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadStringList(out var authThatCanContinue) ||
            !reader.TryReadBoolean(out var partialSuccess))
        {
            payload = default;
            return false;
        }

        payload = new UserauthFailurePacket()
        {
            AuthThatCanContinue = authThatCanContinue,
            PartialSuccess = partialSuccess
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in UserauthFailurePacket payload)
    {
        writer.WriteByte((byte)MessageId.SSH_MSG_USERAUTH_FAILURE);
        writer.WriteStringList(payload.AuthThatCanContinue);
        writer.WriteBoolean(payload.PartialSuccess);
    }
}