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

    private byte[] _sessionId = null!;

    private SshConnectionParameters _parameters = null!;

    private KeyExchange _keyExchange = null!;

    private HostKeyAlgorithm _hostKey = null!;

    private EncryptionAlgorithm _clientToServerEncryption = NullEncryptionAlgorithm.Instance;

    private EncryptionAlgorithm _serverToClientEncryption = NullEncryptionAlgorithm.Instance;

    private MacAlgorithm _clientToServerMac = new NullMacAlgorithm();

    private MacAlgorithm _serverToClientMac = new NullMacAlgorithm();

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

        DoKeyExchange();
        AuthenticateUser();
    }

    private void AuthenticateUser()
    {

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

        SendPacket(clientKexPacket);

        // send initial key exchange packet
        SendPacket(new KeyExchangeEcdhInitPacket
        {
            ClientEphemeralPublicKey = _keyExchange.EphemeralPublicKey,
        });

        var serverKexReply = ExpectMessage<KeyExchangeEcdhReplyPacket>();
        DebugHelpers.DumpKeyExchangeReplyPacket(serverKexReply);

        _keyExchange.DeriveSharedSecret(serverKexReply.ServerEphemeralPublicKey);
        var exchangeHash = _keyExchange.GetExchangeHash(Encoding.UTF8.GetBytes(ServerVersion), Constants.VersionBytes, clientKexPacket, serverKexPacket, serverKexReply);

        _sessionId ??= exchangeHash;

        _hostKey = HostKeyAlgorithm.CreateFromWireData(serverKexReply.HostKey);

        if (!_hostKey.VerifyExchangeHashSignature(exchangeHash, serverKexReply.ExchangeHashSignature))
        {
            throw new Exception("Failed to verify exchange signature.");
        }

        SendPacket(MessageId.SSH_MSG_NEWKEYS);
        ExpectMessage(MessageId.SSH_MSG_NEWKEYS);
        DeriveEncryptionKeys(exchangeHash);
    }

    private void DeriveEncryptionKeys(byte[] exchangeHash)
    {
        //   K = shared secret, H = exchange hash
        //
        //    o  Initial IV client to server: HASH(K || H || "A" || session_id)
        //       (Here K is encoded as mpint and "A" as byte and session_id as raw
        //       data.  "A" means the single character A, ASCII 65).
        // 
        //    o  Initial IV server to client: HASH(K || H || "B" || session_id)
        // 
        //    o  Encryption key client to server: HASH(K || H || "C" || session_id)
        // 
        //    o  Encryption key server to client: HASH(K || H || "D" || session_id)
        // 
        //    o  Integrity key client to server: HASH(K || H || "E" || session_id)
        // 
        //    o  Integrity key server to client: HASH(K || H || "F" || session_id)

        byte[] HashHelper(char c) => _keyExchange.Hash(_keyExchange.SharedSecret!.Concat(exchangeHash).Concat(new byte[] { (byte)c }).Concat(_sessionId).ToArray());

        var clientToServerIv = HashHelper('A');
        var serverToClientIv = HashHelper('B');
        var clientToServerEncryptionKey = HashHelper('C');
        var serverToClientEncryptionKey = HashHelper('D');
        var clientToServerMacKey = HashHelper('E');
        var serverToClientMacKey = HashHelper('F');

        _clientToServerEncryption = EncryptionAlgorithm.Create(_parameters.EncryptionAlgorithmClientToServer, clientToServerIv, clientToServerEncryptionKey);
        _serverToClientEncryption = EncryptionAlgorithm.Create(_parameters.EncryptionAlgorithmServerToClient, serverToClientIv, serverToClientEncryptionKey);

        _clientToServerMac = MacAlgorithm.Create(_parameters.MacAlgorithmClientToServer, _clientToServerMac.SequenceNumber, clientToServerMacKey);
        _serverToClientMac = MacAlgorithm.Create(_parameters.MacAlgorithmServerToClient, _serverToClientMac.SequenceNumber, serverToClientMacKey);
    }

    private T ExpectMessage<T>() where T : IPacketPayload<T>
    {
        var packet = ReadPacket();
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
        var packet = ReadPacket();
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

    private void SendPacket<T>(in T packet) where T : IPacketPayload<T> =>
        _readerWriter.SendPacket(packet, _clientToServerEncryption, _clientToServerMac);

    private void SendPacket(MessageId messageId) =>
        _readerWriter.SendPacket(messageId, _clientToServerEncryption, _clientToServerMac);

    private SshPacket ReadPacket() => _readerWriter.ReadPacket(_serverToClientEncryption, _serverToClientMac);

    public void Dispose()
    {
        _socket.Dispose();
        _readerWriter.Dispose();
    }
}