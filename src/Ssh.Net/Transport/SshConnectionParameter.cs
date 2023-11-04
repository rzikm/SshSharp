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
        return new SshConnectionParameters()
        {
            KeyExchangeAlgorithm = clientKexPacket.KeyExchangeAlgorithms.FirstOrDefault(a => serverKexPacket.KeyExchangeAlgorithms.Contains(a)) ?? throw new Exception("No common key exchange algorithm"),
            ServerHostKeyAlgorithm = clientKexPacket.ServerHostKeyAlgorithms.FirstOrDefault(a => serverKexPacket.ServerHostKeyAlgorithms.Contains(a)) ?? throw new Exception("No common host key algorithm"),
            EncryptionAlgorithmClientToServer = clientKexPacket.EncryptionAlgorithmsClientToServer.FirstOrDefault(a => serverKexPacket.EncryptionAlgorithmsClientToServer.Contains(a)) ?? throw new Exception("No common encryption algorithm (client to server)"),
            EncryptionAlgorithmServerToClient = clientKexPacket.EncryptionAlgorithmsServerToClient.FirstOrDefault(a => serverKexPacket.EncryptionAlgorithmsServerToClient.Contains(a)) ?? throw new Exception("No common encryption algorithm (server to client)"),
            MacAlgorithmClientToServer = clientKexPacket.MacAlgorithmsClientToServer.FirstOrDefault(a => serverKexPacket.MacAlgorithmsClientToServer.Contains(a)) ?? throw new Exception("No common MAC algorithm (client to server)"),
            MacAlgorithmServerToClient = clientKexPacket.MacAlgorithmsServerToClient.FirstOrDefault(a => serverKexPacket.MacAlgorithmsServerToClient.Contains(a)) ?? throw new Exception("No common MAC algorithm (server to client)"),
            CompressionAlgorithmClientToServer = clientKexPacket.CompressionAlgorithmsClientToServer.FirstOrDefault(a => serverKexPacket.CompressionAlgorithmsClientToServer.Contains(a)) ?? throw new Exception("No common compression algorithm (client to server)"),
            CompressionAlgorithmServerToClient = clientKexPacket.CompressionAlgorithmsServerToClient.FirstOrDefault(a => serverKexPacket.CompressionAlgorithmsServerToClient.Contains(a)) ?? throw new Exception("No common compression algorithm (server to client)"),
            LanguageClientToServer = clientKexPacket.LanguagesClientToServer.FirstOrDefault(l => serverKexPacket.LanguagesClientToServer.Contains(l)),
            LanguageServerToClient = clientKexPacket.LanguagesServerToClient.FirstOrDefault(l => serverKexPacket.LanguagesServerToClient.Contains(l)),
        };
    }
}
