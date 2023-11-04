using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct KeyExchangeEcdhInitPacket : IPacketPayload<KeyExchangeEcdhInitPacket>
{
    public int WireLength => GetWireLength();

    public byte[] ClientEphemeralPublicKey { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_KEXDH_INIT;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(ClientEphemeralPublicKey);

        return length;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out KeyExchangeEcdhInitPacket payload, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadStringAsSpan(out var clientEphemeralPublicKey))
        {
            payload = default;
            consumed = buffer.Length - reader.RemainingBytes;
            return false;
        }

        payload = new KeyExchangeEcdhInitPacket()
        {
            ClientEphemeralPublicKey = clientEphemeralPublicKey.ToArray()
        };
        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in KeyExchangeEcdhInitPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);
        writer.WriteByte((byte)MessageId.SSH_MSG_KEXDH_INIT);
        writer.WriteString(packet.ClientEphemeralPublicKey);

        return destination.Length - writer.RemainingBytes;
    }
}