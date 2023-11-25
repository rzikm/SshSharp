using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct UserauthBannerPacket : IPacketPayload<UserauthBannerPacket>
{
    public int WireLength => GetWireLength();

    public string Message { get; set; }
    public string Language { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_USERAUTH_BANNER;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(Message);
        length += DataHelper.GetStringWireLength(Language);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out UserauthBannerPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadString(out var message) ||
            !reader.TryReadString(out var language))
        {
            payload = default;
            return false;
        }

        payload = new UserauthBannerPacket
        {
            Message = message,
            Language = language
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in UserauthBannerPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteString(payload.Message);
        writer.WriteString(payload.Language);
    }
}
