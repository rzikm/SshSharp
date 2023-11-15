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

    public static bool TryRead(ReadOnlySpan<byte> buffer, out UserauthBannerPacket payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadString(out var message) ||
            !reader.TryReadString(out var language))
        {
            consumed = buffer.Length - reader.RemainingBytes;
            payload = default;
            return false;
        }

        payload = new UserauthBannerPacket
        {
            Message = message,
            Language = language
        };

        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in UserauthBannerPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        writer.WriteByte((byte)MessageId);
        writer.WriteString(packet.Message);
        writer.WriteString(packet.Language);

        return destination.Length - writer.RemainingBytes;
    }
}
