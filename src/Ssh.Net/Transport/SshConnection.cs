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

    private KeyExchangeCurve25519 _keyExchange = new KeyExchangeCurve25519();

    private byte[] SecretKey { get; set; } = null!;

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

        _stream.Write("SSH-2.0-SSH_NET_0.0.0\r\n"u8);

        // read key exchange packet
        DoKeyExchange();
    }

    private void DoKeyExchange()
    {
        var serverKexPacket = ExpectMessage<KeyExchangeInitPacket>();
        DebugHelpers.DumpKeyExchangePacket(serverKexPacket);

        var clientKexPacket = new KeyExchangeInitPacket()
        {
            Cookie = serverKexPacket.Cookie,
            // KeyExchangeAlgorithms = new List<string> { "ecdh-sha2-nistp256" },
            KeyExchangeAlgorithms = new List<string> { "curve25519-sha256" },
            // ServerHostKeyAlgorithms = new List<string> { "rsa-sha2-512" },
            ServerHostKeyAlgorithms = serverKexPacket.ServerHostKeyAlgorithms,
            EncryptionAlgorithmsClientToServer = new List<string> { "aes256-ctr" },
            // EncryptionAlgorithmsClientToServer = serverKexPacket.EncryptionAlgorithmsClientToServer,
            EncryptionAlgorithmsServerToClient = new List<string> { "aes256-ctr" },
            // EncryptionAlgorithmsServerToClient = serverKexPacket.EncryptionAlgorithmsServerToClient,
            // MacAlgorithmsClientToServer = new List<string> { "hmac-sha2-512" },
            MacAlgorithmsClientToServer = serverKexPacket.MacAlgorithmsClientToServer,
            // MacAlgorithmsServerToClient = new List<string> { "hmac-sha2-512" },
            MacAlgorithmsServerToClient = serverKexPacket.MacAlgorithmsServerToClient,

            CompressionAlgorithmsClientToServer = new List<string> { "none" },
            CompressionAlgorithmsServerToClient = new List<string> { "none" },
            LanguagesClientToServer = new List<string> { },
            LanguagesServerToClient = new List<string> { },
            FirstKexPacketFollows = false,
            Reserved = 0,
        };

        _parameters = SshConnectionParameters.FromKeyExchangeInitPacket(serverKexPacket, clientKexPacket);

        _readerWriter.SendPacket(clientKexPacket);

        // send initial key exchange packet
        _readerWriter.SendPacket(new KeyExchangeEcdhInitPacket
        {
            ClientEphemeralPublicKey = _keyExchange.PublicKey,
        });

        var serverKexReply = ExpectMessage<KeyExchangeEcdhReplyPacket>();
        ExpectMessage(MessageId.SSH_MSG_NEWKEYS);

        SecretKey = _keyExchange.DeriveSharedSecret(serverKexReply.ServerEphemeralPublicKey);
        _readerWriter.SendPacket(MessageId.SSH_MSG_NEWKEYS);
    }

    private T ExpectMessage<T>() where T : IPacketPayload<T>
    {
        var packet = _readerWriter.ReadPacket();
        if ((MessageId)packet.Payload[0] != T.MessageId)
        {
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