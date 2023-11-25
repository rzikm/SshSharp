using SshSharp.Packets;

namespace SshSharp.Utils;

internal static class DebugHelpers
{
    internal static void DumpKeyExchangePacket(in KeyExchangeInitPacket packet)
    {
        Console.WriteLine($"KeyExchangeAlgorithms: {string.Join(",", packet.KeyExchangeAlgorithms)}");
        Console.WriteLine($"ServerHostKeyAlgorithms: {string.Join(",", packet.ServerHostKeyAlgorithms)}");
        Console.WriteLine($"EncryptionAlgorithmsClientToServer: {string.Join(",", packet.EncryptionAlgorithmsClientToServer)}");
        Console.WriteLine($"EncryptionAlgorithmsServerToClient: {string.Join(",", packet.EncryptionAlgorithmsServerToClient)}");
        Console.WriteLine($"MacAlgorithmsClientToServer: {string.Join(",", packet.MacAlgorithmsClientToServer)}");
        Console.WriteLine($"MacAlgorithmsServerToClient: {string.Join(",", packet.MacAlgorithmsServerToClient)}");
        Console.WriteLine($"CompressionAlgorithmsClientToServer: {string.Join(",", packet.CompressionAlgorithmsClientToServer)}");
        Console.WriteLine($"CompressionAlgorithmsServerToClient: {string.Join(",", packet.CompressionAlgorithmsServerToClient)}");
        Console.WriteLine($"LanguagesClientToServer: {string.Join(",", packet.LanguagesClientToServer)}");
        Console.WriteLine($"LanguagesServerToClient: {string.Join(",", packet.LanguagesServerToClient)}");
        Console.WriteLine($"FirstKexPacketFollows: {packet.FirstKexPacketFollows}");
        Console.WriteLine($"Reserved: {packet.Reserved}");
        System.Console.WriteLine();
    }

    internal static void DumpKeyExchangeReplyPacket(in KeyExchangeEcdhReplyPacket packet)
    {
        Console.WriteLine(KeyExchangeEcdhReplyPacket.MessageId);
        Console.WriteLine($"HostKey: {BitConverter.ToString(packet.HostKey)}");
        Console.WriteLine($"ServerEphemeralPublicKey: {BitConverter.ToString(packet.ServerEphemeralPublicKey)}");
        Console.WriteLine($"ExchangeHashSignature: {BitConverter.ToString(packet.ExchangeHashSignature)}");
        System.Console.WriteLine();
    }
}