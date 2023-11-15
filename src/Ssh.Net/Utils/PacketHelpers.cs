using Ssh.Net.Crypto;
using Ssh.Net.Packets;

namespace Ssh.Net.Utils;

internal static class PacketHelpers
{
    public static int WritePayload<T>(Span<byte> destination, T packet) where T : IPacketPayload<T> => WritePayload(destination, packet, NullEncryptionAlgorithm.Instance, NullMacAlgorithm.Instance);
    public static int WritePayload<T>(Span<byte> destination, T packet, EncryptionAlgorithm encryption, MacAlgorithm mac) where T : IPacketPayload<T>
    {
        Span<byte> payload = stackalloc byte[packet.WireLength];
        int written = T.Write(payload, packet);

        return WritePayload(destination, payload.Slice(0, written), encryption, mac);
    }

    public static int WritePayload(Span<byte> destination, ReadOnlySpan<byte> payload) => WritePayload(destination, payload, NullEncryptionAlgorithm.Instance, NullMacAlgorithm.Instance);

    public static int WritePayload(Span<byte> destination, ReadOnlySpan<byte> payload, EncryptionAlgorithm encryption, MacAlgorithm mac)
    {
        // at least 4 bytes of padding, add another 8 to make sure we can subtract up to 8 bytes for alignment
        int padding = Random.Shared.Next(20, 30);
        int lenWithoutMac = 5 + payload.Length + padding;

        // length without mac must be divisible by 8 or block size, whichever is higher
        padding -= lenWithoutMac % encryption.BlockSize;
        lenWithoutMac -= lenWithoutMac % encryption.BlockSize;

        Span<byte> paddingSpan = stackalloc byte[padding];

        SshPacket sshPacket = new SshPacket
        {
            Payload = payload,
            Padding = paddingSpan,
            Mac = Span<byte>.Empty
        };

        SshPacket.Write(destination, sshPacket);

        mac.Sign(destination.Slice(0, lenWithoutMac), destination.Slice(lenWithoutMac, mac.MacSize));
        encryption.Encrypt(destination.Slice(0, lenWithoutMac));

        return sshPacket.WireLength + mac.MacSize;
    }
}