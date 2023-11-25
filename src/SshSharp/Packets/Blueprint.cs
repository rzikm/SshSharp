using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct Blueprint : IPacketPayload<Blueprint>
{
    public int WireLength => GetWireLength();

    public static MessageId MessageId => throw new NotImplementedException();

    private int GetWireLength()
    {
        var length = 1;

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out Blueprint payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId)
        {
            payload = default;
            return false;
        }

        payload = new Blueprint();
        return true;
    }

    public static void Write(ref SpanWriter writer, in Blueprint payload)
    {
        writer.WriteByte((byte)MessageId);
    }
}