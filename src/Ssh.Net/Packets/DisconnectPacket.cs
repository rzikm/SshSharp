using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct DisconnectPacket : IPacketPayload<DisconnectPacket>
{
    public uint ReasonCode { get; set; }
    public string Description { get; set; }
    public string LanguageTag { get; set; }

    public int WireLength => GetWireLength();

    public static MessageId MessageId => throw new NotImplementedException();

    private int GetWireLength()
    {
        var length = 1;

        length += 4; // ReasonCode
        length += DataHelper.GetStringWireLength(Description);
        length += DataHelper.GetStringWireLength(LanguageTag);

        return length;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out DisconnectPacket payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadUInt32(out var reasonCode) ||
            !reader.TryReadString(out var description) ||
            !reader.TryReadString(out var languageTag))
        {
            payload = default;
            consumed = buffer.Length - reader.RemainingBytes;
            return false;
        }

        payload = new DisconnectPacket()
        {
            ReasonCode = reasonCode,
            Description = description,
            LanguageTag = languageTag
        };
        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in DisconnectPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        writer.WriteByte((byte)MessageId.SSH_MSG_DISCONNECT);
        writer.WriteUInt32(packet.ReasonCode);
        writer.WriteString(packet.Description);
        writer.WriteString(packet.LanguageTag);

        return destination.Length - writer.RemainingBytes;
    }
}