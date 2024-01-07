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
}