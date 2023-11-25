using SshSharp.Packets;

namespace SshSharp.Unit.Tests;

public class SshPacketTests
{
    [Fact]
    public void TryRead_WhenBufferIsTooSmall_ReturnsFalse()
    {
        var buffer = new byte[4];
        var macLength = 2;

        var result = SshPacket.TryRead(buffer, macLength, out _, out var consumed);

        Assert.False(result);
        Assert.Equal(5, consumed);
    }

    [Fact]
    public void TryRead_WhenPacketIsIncomplete_ReturnsFalseAndLength()
    {
        var buffer = new byte[5];
        buffer[3] = 20;
        var macLength = 2;

        var result = SshPacket.TryRead(buffer, macLength, out _, out var consumed);

        Assert.False(result);
        Assert.Equal(SshPacket.GetExpectedLength(20, macLength), consumed);
    }

    [Fact]
    public void TryRead_WhenBufferIsLargeEnough_ReturnsTrue()
    {
        var buffer = new byte[5];
        buffer[3] = 1;

        var macLength = 0;

        var result = SshPacket.TryRead(buffer, macLength, out var packet, out var consumed);

        Assert.True(result);
        Assert.Equal(5, consumed);
        Assert.Equal(packet.WireLength, consumed);
    }

    [Fact]
    public void Write_WhenDestinationBufferIsTooSmall_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            var packet = new SshPacket();
            var destination = new byte[packet.WireLength - 1];

            SshPacket.Write(destination, packet);
        });
    }

    [Fact]
    public void Write_AndReadBack_ReturnsSamePacket()
    {
        var packet = new SshPacket
        {
            Payload = new byte[] { 1, 2, 3 },
            Padding = new byte[] { 4, 5 },
            Mac = new byte[] { 6, 7, 8 }
        };

        var destination = new byte[packet.WireLength];

        SshPacket.Write(destination, packet);

        var result = SshPacket.TryRead(destination, packet.Mac.Length, out var readPacket, out var consumed);

        Assert.True(result);
        Assert.Equal(packet.WireLength, consumed);
        Assert.Equal(packet.Payload.ToArray(), readPacket.Payload.ToArray());
        Assert.Equal(packet.Padding.ToArray(), readPacket.Padding.ToArray());
        Assert.Equal(packet.Mac.ToArray(), readPacket.Mac.ToArray());
    }
}