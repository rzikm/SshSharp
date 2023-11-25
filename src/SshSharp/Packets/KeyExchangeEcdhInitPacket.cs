using SshSharp.Utils;

namespace SshSharp.Packets;

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

    public static bool TryRead(ref SpanReader reader, out KeyExchangeEcdhInitPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadStringAsSpan(out var clientEphemeralPublicKey))
        {
            payload = default;
            return false;
        }

        payload = new KeyExchangeEcdhInitPacket()
        {
            ClientEphemeralPublicKey = clientEphemeralPublicKey.ToArray()
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in KeyExchangeEcdhInitPacket payload)
    {
        writer.WriteByte((byte)MessageId.SSH_MSG_KEXDH_INIT);
        writer.WriteString(payload.ClientEphemeralPublicKey);
    }
}