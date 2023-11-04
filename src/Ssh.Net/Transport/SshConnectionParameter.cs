using Ssh.Net.Packets;

namespace Ssh.Net.Transport;

internal class SshConnectionParameters
{
    internal string KeyExchangeAlgorithm { get; init; } = null!;
    internal string ServerHostKeyAlgorithm { get; init; } = null!;
    internal string EncryptionAlgorithmClientToServer { get; init; } = null!;
    internal string EncryptionAlgorithmServerToClient { get; init; } = null!;
    internal string MacAlgorithmClientToServer { get; init; } = null!;
    internal string MacAlgorithmServerToClient { get; init; } = null!;
    internal string CompressionAlgorithmClientToServer { get; init; } = null!;
    internal string CompressionAlgorithmServerToClient { get; init; } = null!;
    internal string? LanguageClientToServer { get; init; }
    internal string? LanguageServerToClient { get; init; }

    internal static SshConnectionParameters FromKeyExchangeInitPacket(KeyExchangeInitPacket serverKexPacket, KeyExchangeInitPacket clientKexPacket)
    {
        // TODO: proper negotiation

        return new SshConnectionParameters()
        {
            KeyExchangeAlgorithm = clientKexPacket.KeyExchangeAlgorithms[0],
            ServerHostKeyAlgorithm = clientKexPacket.ServerHostKeyAlgorithms[0],
            EncryptionAlgorithmClientToServer = clientKexPacket.EncryptionAlgorithmsClientToServer[0],
            EncryptionAlgorithmServerToClient = clientKexPacket.EncryptionAlgorithmsServerToClient[0],
            MacAlgorithmClientToServer = clientKexPacket.MacAlgorithmsClientToServer[0],
            MacAlgorithmServerToClient = clientKexPacket.MacAlgorithmsServerToClient[0],
            CompressionAlgorithmClientToServer = clientKexPacket.CompressionAlgorithmsClientToServer[0],
            CompressionAlgorithmServerToClient = clientKexPacket.CompressionAlgorithmsServerToClient[0],
            LanguageClientToServer = clientKexPacket.LanguagesClientToServer.FirstOrDefault(),
            LanguageServerToClient = clientKexPacket.LanguagesServerToClient.FirstOrDefault(),
        };
    }
}
