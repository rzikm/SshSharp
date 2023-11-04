using Ssh.Net.Utils;

namespace Ssh.Net.Packets;

internal struct KeyExchangeInitPacket : IPacketPayload<KeyExchangeInitPacket>
{
    public UInt128 Cookie { get; set; }
    public List<string> KeyExchangeAlgorithms { get; set; }
    public List<string> ServerHostKeyAlgorithms { get; set; }
    public List<string> EncryptionAlgorithmsClientToServer { get; set; }
    public List<string> EncryptionAlgorithmsServerToClient { get; set; }
    public List<string> MacAlgorithmsClientToServer { get; set; }
    public List<string> MacAlgorithmsServerToClient { get; set; }
    public List<string> CompressionAlgorithmsClientToServer { get; set; }
    public List<string> CompressionAlgorithmsServerToClient { get; set; }
    public List<string> LanguagesClientToServer { get; set; }
    public List<string> LanguagesServerToClient { get; set; }
    public bool FirstKexPacketFollows { get; set; }
    public uint Reserved { get; set; }

    public int WireLength => GetWireLength();

    public static MessageId MessageId => MessageId.SSH_MSG_KEXINIT;

    private int GetWireLength()
    {
        var length = 1;

        length += 16; // cookie
        length += DataHelper.GetStringListWireLength(KeyExchangeAlgorithms);
        length += DataHelper.GetStringListWireLength(ServerHostKeyAlgorithms);
        length += DataHelper.GetStringListWireLength(EncryptionAlgorithmsClientToServer);
        length += DataHelper.GetStringListWireLength(EncryptionAlgorithmsServerToClient);
        length += DataHelper.GetStringListWireLength(MacAlgorithmsClientToServer);
        length += DataHelper.GetStringListWireLength(MacAlgorithmsServerToClient);
        length += DataHelper.GetStringListWireLength(CompressionAlgorithmsClientToServer);
        length += DataHelper.GetStringListWireLength(CompressionAlgorithmsServerToClient);
        length += DataHelper.GetStringListWireLength(LanguagesClientToServer);
        length += DataHelper.GetStringListWireLength(LanguagesServerToClient);
        length += 1; // firstKexPacketFollows
        length += 4; // Reserved;

        return length;
    }

    public static bool TryRead(ReadOnlySpan<byte> buffer, out KeyExchangeInitPacket packet, out int consumed)
    {
        var reader = new SpanReader(buffer.Slice(1)); // skip message id

        if (!reader.TryReadUInt128(out var cookie) ||
            !reader.TryReadStringList(out var keyExchangeAlgorithms) ||
            !reader.TryReadStringList(out var serverHostKeyAlgorithms) ||
            !reader.TryReadStringList(out var encryptionAlgorithmsClientToServer) ||
            !reader.TryReadStringList(out var encryptionAlgorithmsServerToClient) ||
            !reader.TryReadStringList(out var macAlgorithmsClientToServer) ||
            !reader.TryReadStringList(out var macAlgorithmsServerToClient) ||
            !reader.TryReadStringList(out var compressionAlgorithmsClientToServer) ||
            !reader.TryReadStringList(out var compressionAlgorithmsServerToClient) ||
            !reader.TryReadStringList(out var languagesClientToServer) ||
            !reader.TryReadStringList(out var languagesServerToClient) ||
            !reader.TryReadBoolean(out var firstKexPacketFollows) ||
            !reader.TryReadUInt32(out var reserved))
        {
            packet = default;
            consumed = buffer.Length - reader.RemainingBytes;
            return false;
        }

        packet = new KeyExchangeInitPacket
        {
            Cookie = cookie,
            KeyExchangeAlgorithms = keyExchangeAlgorithms,
            ServerHostKeyAlgorithms = serverHostKeyAlgorithms,
            EncryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer,
            EncryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient,
            MacAlgorithmsClientToServer = macAlgorithmsClientToServer,
            MacAlgorithmsServerToClient = macAlgorithmsServerToClient,
            CompressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer,
            CompressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient,
            LanguagesClientToServer = languagesClientToServer,
            LanguagesServerToClient = languagesServerToClient,
            FirstKexPacketFollows = firstKexPacketFollows,
            Reserved = reserved
        };

        consumed = buffer.Length - reader.RemainingBytes;
        return true;
    }

    public static int Write(Span<byte> destination, in KeyExchangeInitPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        writer.WriteByte((byte)MessageId.SSH_MSG_KEXINIT);
        writer.WriteUInt128(packet.Cookie);
        writer.WriteStringList(packet.KeyExchangeAlgorithms);
        writer.WriteStringList(packet.ServerHostKeyAlgorithms);
        writer.WriteStringList(packet.EncryptionAlgorithmsClientToServer);
        writer.WriteStringList(packet.EncryptionAlgorithmsServerToClient);
        writer.WriteStringList(packet.MacAlgorithmsClientToServer);
        writer.WriteStringList(packet.MacAlgorithmsServerToClient);
        writer.WriteStringList(packet.CompressionAlgorithmsClientToServer);
        writer.WriteStringList(packet.CompressionAlgorithmsServerToClient);
        writer.WriteStringList(packet.LanguagesClientToServer);
        writer.WriteStringList(packet.LanguagesServerToClient);
        writer.WriteBoolean(packet.FirstKexPacketFollows);
        writer.WriteUInt32(packet.Reserved);

        return destination.Length - writer.RemainingBytes;
    }
}