using System.Buffers.Binary;

namespace Ssh.Net.Packets;

internal ref struct SshPacket
{
    public ReadOnlySpan<byte> Payload { get; set; }
    public ReadOnlySpan<byte> Padding { get; set; }
    public ReadOnlySpan<byte> Mac { get; set; }

    public int WireLength => 4 + 1 + Payload.Length + Padding.Length + Mac.Length;

    public static int GetExpectedLength(int packetLength, int macLength) => packetLength + 4 + macLength;

    public static bool TryRead(ReadOnlySpan<byte> buffer, int macLength, out SshPacket packet, out int consumed)
    {
        packet = default;
        consumed = 5;

        if (buffer.Length < 5)
        {
            return false;
        }

        var packetLength = BinaryPrimitives.ReadUInt32BigEndian(buffer);
        consumed = 4 + (int)packetLength + macLength;

        if (packetLength < 1)
        {
            throw new ArgumentException("Corrupted packet length.");
        }

        var paddingLength = buffer[4];

        if (buffer.Length < packetLength + macLength + 4)
        {
            // too small, wait for more data
            return false;
        }

        var payloadLength = (int)packetLength - paddingLength - 1;

        packet = new SshPacket
        {
            Payload = buffer.Slice(5, payloadLength),
            Padding = buffer.Slice(5 + payloadLength, paddingLength),
            Mac = buffer.Slice(5 + payloadLength + paddingLength, macLength)
        };

        return true;
    }

    public static void Write(Span<byte> destination, in SshPacket packet)
    {
        if (destination.Length < packet.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        int packetLength = packet.Payload.Length + packet.Padding.Length + 1;

        BinaryPrimitives.WriteUInt32BigEndian(destination, (uint)packetLength);
        destination[4] = (byte)packet.Padding.Length;

        packet.Payload.CopyTo(destination.Slice(5));
        packet.Padding.CopyTo(destination.Slice(5 + packet.Payload.Length));
        packet.Mac.CopyTo(destination.Slice(5 + packet.Payload.Length + packet.Padding.Length));
    }
}