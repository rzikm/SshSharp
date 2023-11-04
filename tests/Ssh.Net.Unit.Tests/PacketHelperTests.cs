using Ssh.Net.Utils;

namespace Ssh.Net.Unit.Tests;

public class PacketHelperTests
{
    [Fact]
    public void WritePayload_WriteAndReadBack()
    {
        KeyExchangeInitPacket payload = new KeyExchangeInitPacket
        {
            Cookie = (UInt128)Random.Shared.NextInt64(),
            KeyExchangeAlgorithms = new List<string> { "aaa" },
            ServerHostKeyAlgorithms = new List<string> { "bbb", "bbbbb" },
            EncryptionAlgorithmsClientToServer = new List<string> { "ccc", "f" },
            EncryptionAlgorithmsServerToClient = new List<string> { },
            MacAlgorithmsClientToServer = new List<string> { "eee" },
            MacAlgorithmsServerToClient = new List<string> { "fff" },
            CompressionAlgorithmsClientToServer = new List<string> { "ggg" },
            CompressionAlgorithmsServerToClient = new List<string> { "hhh" },
            LanguagesClientToServer = new List<string> { "iii" },
            LanguagesServerToClient = new List<string> { "jjj" },
            FirstKexPacketFollows = true
        };

        Span<byte> buffer = stackalloc byte[1024];

        int written = PacketHelpers.WritePayload(buffer, payload);

        Assert.Equal(0, (written - 4) % 8);

        Assert.True(SshPacket.TryRead(buffer, 0, out var packet, out var read));
        Assert.Equal(written, read);
        Assert.Equal(payload.WireLength, packet.Payload.Length);

        Assert.True(KeyExchangeInitPacket.TryRead(packet.Payload, out var readPayload, out var packetRead));
        Assert.Equal(payload.WireLength, packetRead);

        Assert.Equal(payload.Cookie, readPayload.Cookie);
        Assert.Equal(payload.KeyExchangeAlgorithms, readPayload.KeyExchangeAlgorithms);
        Assert.Equal(payload.ServerHostKeyAlgorithms, readPayload.ServerHostKeyAlgorithms);
        Assert.Equal(payload.EncryptionAlgorithmsClientToServer, readPayload.EncryptionAlgorithmsClientToServer);
        Assert.Equal(payload.EncryptionAlgorithmsServerToClient, readPayload.EncryptionAlgorithmsServerToClient);
        Assert.Equal(payload.MacAlgorithmsClientToServer, readPayload.MacAlgorithmsClientToServer);
        Assert.Equal(payload.MacAlgorithmsServerToClient, readPayload.MacAlgorithmsServerToClient);
        Assert.Equal(payload.CompressionAlgorithmsClientToServer, readPayload.CompressionAlgorithmsClientToServer);
        Assert.Equal(payload.CompressionAlgorithmsServerToClient, readPayload.CompressionAlgorithmsServerToClient);
        Assert.Equal(payload.LanguagesClientToServer, readPayload.LanguagesClientToServer);
        Assert.Equal(payload.LanguagesServerToClient, readPayload.LanguagesServerToClient);
        Assert.Equal(payload.FirstKexPacketFollows, readPayload.FirstKexPacketFollows);
    }
}