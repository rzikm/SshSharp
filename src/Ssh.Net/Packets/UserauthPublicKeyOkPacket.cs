using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct UserauthPublicKeyOkPacket : IPacketPayload<UserauthPublicKeyOkPacket>
{
    public int WireLength => GetWireLength();

    public string AlgorithmName { get; set; }

    public byte[] PublicKey { get; set; }

    public static MessageId MessageId => MessageId.SSH_MSG_USERAUTH_PK_OK;

    private int GetWireLength()
    {
        var length = 1;

        length += DataHelper.GetStringWireLength(AlgorithmName);
        length += DataHelper.GetStringWireLength(PublicKey);

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out UserauthPublicKeyOkPacket payload)
    {
        if (!reader.TryReadByte(out var messageId) || messageId != (byte)MessageId ||
            !reader.TryReadString(out var algorithmName) ||
            !reader.TryReadStringAsSpan(out var publicKey))
        {
            payload = default;
            return false;
        }

        payload = new UserauthPublicKeyOkPacket()
        {
            AlgorithmName = algorithmName,
            PublicKey = publicKey.ToArray()
        };

        return true;
    }

    public static void Write(ref SpanWriter writer, in UserauthPublicKeyOkPacket payload)
    {
        writer.WriteByte((byte)MessageId);
        writer.WriteString(payload.AlgorithmName);
        writer.WriteString(payload.PublicKey);
    }
}