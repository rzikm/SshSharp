using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

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

    public static bool TryRead(ReadOnlySpan<byte> buffer, out UserauthFailurePacket payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadStringList(out var authThatCanContinue) ||
            !reader.TryReadBoolean(out var partialSuccess))
        {
            consumed = buffer.Length - reader.RemainingBytes;
            payload = default;
            return false;
        }

        payload = new UserauthFailurePacket()
        {
            AuthThatCanContinue = authThatCanContinue,
            PartialSuccess = partialSuccess
        };

        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in UserauthFailurePacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        writer.WriteByte((byte)MessageId.SSH_MSG_USERAUTH_FAILURE);
        writer.WriteStringList(packet.AuthThatCanContinue);
        writer.WriteBoolean(packet.PartialSuccess);

        return destination.Length - writer.RemainingBytes;
    }
}