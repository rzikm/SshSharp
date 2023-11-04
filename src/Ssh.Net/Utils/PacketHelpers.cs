namespace Ssh.Net.Utils;

internal static class PacketHelpers
{
    public static int WritePayload<T>(Span<byte> destination, T packet) where T : IPacketPayload<T>
    {
        Span<byte> buffer = stackalloc byte[packet.WireLength];
        int written = T.Write(buffer, packet);

        // at least 4 bytes of padding, add another 8 to make sure we can subtract up to 8 bytes for alignment
        int padding = Random.Shared.Next(8, 256);

        int lenWithoutMac = 5 + written + padding;

        // length without mac must be divisible by 8 or block size, whichever is higher
        padding -= lenWithoutMac % 8;
        lenWithoutMac -= lenWithoutMac % 8;

        Span<byte> paddingSpan = stackalloc byte[padding];

        SshPacket sshPacket = new SshPacket
        {
            Payload = buffer,
            Padding = paddingSpan,
            Mac = Span<byte>.Empty
        };

        SshPacket.Write(sshPacket, destination);
        return sshPacket.WireLength;
    }
}