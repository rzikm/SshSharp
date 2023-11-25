using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct KeyExchangeEcdhReplyPacket : IPacketPayload<KeyExchangeEcdhReplyPacket>
{
    public int WireLength => GetWireLength();

    public byte[] HostKey { get; set; }
    public byte[] ServerEphemeralPublicKey { get; set; }
    public byte[] ExchangeHashSignature { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_KEXDH_REPLY;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(HostKey);
        length += DataHelper.GetStringWireLength(ServerEphemeralPublicKey);
        length += DataHelper.GetStringWireLength(ExchangeHashSignature);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out KeyExchangeEcdhReplyPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadStringAsSpan(out var hostKey) ||
            !reader.TryReadStringAsSpan(out var serverEphemeralPublicKey) ||
            !reader.TryReadStringAsSpan(out var exchangeHashSignature))
        {
            payload = default;
            return false;
        }

        payload = new KeyExchangeEcdhReplyPacket()
        {
            HostKey = hostKey.ToArray(),
            ServerEphemeralPublicKey = serverEphemeralPublicKey.ToArray(),
            ExchangeHashSignature = exchangeHashSignature.ToArray()
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in KeyExchangeEcdhReplyPacket payload)
    {
        writer.WriteByte((byte)MessageId.SSH_MSG_KEXDH_REPLY);
        writer.WriteString(payload.HostKey);
        writer.WriteString(payload.ServerEphemeralPublicKey);
        writer.WriteString(payload.ExchangeHashSignature);
    }
}