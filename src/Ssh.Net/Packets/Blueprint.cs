using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct Blueprint : IPacketPayload<Blueprint>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => throw new NotImplementedException();

    private int GetWireLength()
    {
        var length = 1;

        return length;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out Blueprint payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        payload = new Blueprint();
        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in Blueprint packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);
        writer.WriteByte((byte)MessageId);

        return destination.Length - writer.RemainingBytes;
    }
}