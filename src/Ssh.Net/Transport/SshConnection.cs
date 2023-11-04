using System.Net;
using System.Net.Sockets;
using System.Text;
using Ssh.Net.Crypto;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Transport;

internal class SshConnection : IDisposable
{
    // private bool _disposed;

    public string ServerVersion { get; private set; } = null!;

    private readonly Socket _socket;

    private readonly NetworkStream _stream;

    private readonly PacketReaderWriter _readerWriter;

    private SshConnectionParameters _parameters = null!;

    private KeyExchange _keyExchange = null!;

    public SshConnection(Socket socket)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
        _readerWriter = new PacketReaderWriter(_stream);
    }

    public static SshConnection Connect(EndPoint endPoint)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(endPoint);

        var conn = new SshConnection(socket);
        conn.DoHandshake();
        return conn;
    }

    private void DoHandshake()
    {
        // exchange versions
        ServerVersion = ReadVersionString();
        System.Console.WriteLine($"Server version: {ServerVersion}");

        _stream.Write(Constants.VersionBytesCrLf);

        // read key exchange packet
        DoKeyExchange();
    }

    private void DoKeyExchange()
    {
        var serverKexPacket = ExpectMessage<KeyExchangeInitPacket>();
        DebugHelpers.DumpKeyExchangePacket(serverKexPacket);

        var clientKexPacket = new KeyExchangeInitPacket()
        {
            Cookie = (UInt128)Random.Shared.NextInt64() + ((UInt128)Random.Shared.NextInt64()) << 64,
            KeyExchangeAlgorithms = new List<string> { "curve25519-sha256" },
            ServerHostKeyAlgorithms = new List<string> { "rsa-sha2-512" },
            EncryptionAlgorithmsClientToServer = new List<string> { "aes256-ctr" },
            EncryptionAlgorithmsServerToClient = new List<string> { "aes256-ctr" },
            MacAlgorithmsClientToServer = new List<string> { "hmac-sha1" },
            MacAlgorithmsServerToClient = new List<string> { "hmac-sha1" },
            CompressionAlgorithmsClientToServer = new List<string> { "none" },
            CompressionAlgorithmsServerToClient = new List<string> { "none" },
            LanguagesClientToServer = new List<string> { },
            LanguagesServerToClient = new List<string> { },
            FirstKexPacketFollows = false,
            Reserved = 0,
        };

        _parameters = SshConnectionParameters.FromKeyExchangeInitPacket(serverKexPacket, clientKexPacket);
        _keyExchange = KeyExchange.Create(_parameters.KeyExchangeAlgorithm);

        _readerWriter.SendPacket(clientKexPacket);

        // send initial key exchange packet
        _readerWriter.SendPacket(new KeyExchangeEcdhInitPacket
        {
            ClientEphemeralPublicKey = _keyExchange.EphemeralPublicKey,
        });

        var serverKexReply = ExpectMessage<KeyExchangeEcdhReplyPacket>();
        DebugHelpers.DumpKeyExchangeReplyPacket(serverKexReply);

        if (!_keyExchange.VerifyExchangeSignature(Encoding.UTF8.GetBytes(ServerVersion), Constants.VersionBytes, clientKexPacket, serverKexPacket, serverKexReply))
        {
            throw new Exception("Failed to verify exchange signature.");
        }

        ExpectMessage(MessageId.SSH_MSG_NEWKEYS);

        _readerWriter.SendPacket(MessageId.SSH_MSG_NEWKEYS);
    }

    private T ExpectMessage<T>() where T : IPacketPayload<T>
    {
        var packet = _readerWriter.ReadPacket();
        if ((MessageId)packet.Payload[0] != T.MessageId)
        {
            if ((MessageId)packet.Payload[0] == MessageId.SSH_MSG_DISCONNECT)
            {
                if (DisconnectPacket.TryRead(packet.Payload, out var disconnectPacket, out _))
                {
                    throw new Exception($"Disconnected: [{disconnectPacket.ReasonCode}] {disconnectPacket.Description}");
                }
            }

            throw new Exception($"Expected {T.MessageId}, got {(MessageId)packet.Payload[0]}.");
        }

        if (!T.TryRead(packet.Payload, out var payload, out _))
        {
            throw new Exception($"Failed to read {typeof(T).Name}.");
        }

        return payload;
    }

    private void ExpectMessage(MessageId messageId)
    {
        var packet = _readerWriter.ReadPacket();
        if ((MessageId)packet.Payload[0] != messageId)
        {
            if ((MessageId)packet.Payload[0] == MessageId.SSH_MSG_DISCONNECT)
            {
                if (DisconnectPacket.TryRead(packet.Payload, out var disconnectPacket, out _))
                {
                    throw new Exception($"Disconnected: [{disconnectPacket.ReasonCode}] {disconnectPacket.Description}");
                }
            }

            throw new Exception($"Expected {messageId}, got {(MessageId)packet.Payload[0]}.");
        }
    }

    private string ReadVersionString()
    {
        return Encoding.UTF8.GetString(_readerWriter.ReadVersionString());
    }

    public void Dispose()
    {
        _socket.Dispose();
        _readerWriter.Dispose();
    }
}