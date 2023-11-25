using System.Buffers.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        SendPacket(new ServiceRequestPacket
        {
            ServiceName = "ssh-userauth"
        });
        ExpectMessage(MessageId.SSH_MSG_SERVICE_ACCEPT);

        SshPublicKey publicKey = SshPublicKey.FromPrivateKeyFile(@"C:\Users\radekzikmund\.ssh\id_rsa");

        var header = new UserAuthRequestHeader
        {
            Username = "EUROPE\\radekzikmund",
            ServiceName = "ssh-connection",
        };

        bool authenticated = false;

        Span<byte> signatureSrc = stackalloc byte[2048];

        foreach (var authAlg in publicKey.GetAlgorithms())
        {
            System.Console.WriteLine($"Attempting auth via: {authAlg.AlgorithmName}");

            var publicKeyData = new UserauthPublicKeyData
            {
                AlgorithmName = authAlg.AlgorithmName,
                PublicKey = authAlg.PublicKey
            };

            SendPacket(header, publicKeyData);

            var replyPacket = ReadPacket();
            if (replyPacket.MessageId == MessageId.SSH_MSG_USERAUTH_FAILURE)
            {
                System.Console.WriteLine($"Rejected: {authAlg.AlgorithmName}");

                var failurePacket = replyPacket.ParsePayload<UserauthFailurePacket>();
                // Console.WriteLine($"Auth methods: {string.Join(", ", failurePacket.AuthThatCanContinue)}");
                // Console.WriteLine($"PartialSuccess: {failurePacket.PartialSuccess}");
                continue;
            }

            {
                var packet = replyPacket.ParsePayload<UserauthPublicKeyOkPacket>();
                if (packet.AlgorithmName != publicKeyData.AlgorithmName)
                {
                    throw new Exception($"Server accepted different algorithm: {packet.AlgorithmName}.");
                }
                if (!packet.PublicKey.AsSpan().SequenceEqual(publicKeyData.PublicKey))
                {
                    throw new Exception($"Server accepted different public key.");
                }
                Console.WriteLine("Public key accepted, retrying with signature.");
            }

            // temporarily put empty array in signature to force TRUE in the "has signature" field for signature computation
            publicKeyData.Signature = Array.Empty<byte>();

            SpanWriter writer = new(signatureSrc);
            writer.WriteString(_sessionId);
            UserAuthRequestHeader.Write(ref writer, header);
            UserauthPublicKeyData.Write(ref writer, publicKeyData);
            signatureSrc = signatureSrc.Slice(0, signatureSrc.Length - writer.RemainingBytes - 4);

            publicKeyData.Signature = authAlg.GetSignature(signatureSrc);

            SendPacket(header, publicKeyData);
            ExpectMessage(MessageId.SSH_MSG_USERAUTH_SUCCESS);
            authenticated = true;
            break;
        }

        if (authenticated)
        {
            Console.WriteLine("User auth successful");
        }
    }

    private void DoKeyExchange()
    {
        var serverKexPacket = ExpectMessage<KeyExchangeInitPacket>();
        // DebugHelpers.DumpKeyExchangePacket(serverKexPacket);

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
        // DebugHelpers.DumpKeyExchangeReplyPacket(serverKexReply);

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

        byte[] HashHelper(char c, int len) => KeyGenerationHelpers.DeriveSessionKey(_keyExchange.SharedSecret, exchangeHash, c, _sessionId, _keyExchange, len);

        _clientToServerEncryption = EncryptionAlgorithm.Create(_parameters.EncryptionAlgorithmClientToServer,
            l => HashHelper('A', l),
            l => HashHelper('C', l));

        _serverToClientEncryption = EncryptionAlgorithm.Create(_parameters.EncryptionAlgorithmServerToClient,
            l => HashHelper('B', l),
            l => HashHelper('D', l));

        _clientToServerMac = MacAlgorithm.Create(_parameters.MacAlgorithmClientToServer, _clientToServerMac.SequenceNumber, l => HashHelper('E', l));
        _serverToClientMac = MacAlgorithm.Create(_parameters.MacAlgorithmClientToServer, _clientToServerMac.SequenceNumber, l => HashHelper('F', l));
    }

    private T ExpectMessage<T>() where T : IPacketPayload<T>
    {
        var packet = ReadPacket();
        if (packet.MessageId != T.MessageId)
        {
            if (packet.MessageId == MessageId.SSH_MSG_DISCONNECT)
            {
                if (packet.TryParsePayload(out DisconnectPacket disconnectPacket, out _))
                {
                    throw new Exception($"Disconnected: [{disconnectPacket.ReasonCode}] {disconnectPacket.Description}");
                }
            }

            throw new Exception($"Expected {T.MessageId}, got {packet.MessageId}.");
        }

        return packet.ParsePayload<T>();
    }

    private void ExpectMessage(MessageId messageId)
    {
        var packet = ReadPacket();
        if (packet.MessageId != messageId)
        {
            if (packet.MessageId == MessageId.SSH_MSG_DISCONNECT)
            {
                if (packet.TryParsePayload(out DisconnectPacket disconnectPacket, out _))
                {
                    throw new Exception($"Disconnected: [{disconnectPacket.ReasonCode}] {disconnectPacket.Description}");
                }
            }

            throw new Exception($"Expected {messageId}, got {packet.MessageId}.");
        }
    }

    private string ReadVersionString()
    {
        return Encoding.UTF8.GetString(_readerWriter.ReadVersionString());
    }

    private void SendPacket<TPacket>(in TPacket packet) where TPacket : IPacketPayload<TPacket> =>
        _readerWriter.SendPacket(packet, _clientToServerEncryption, _clientToServerMac);

    private void SendPacket<TAuth>(in UserAuthRequestHeader header, in TAuth auth) where TAuth : IUserauthMethod<TAuth> =>
        _readerWriter.SendPacket(header, auth, _clientToServerEncryption, _clientToServerMac);

    private void SendPacket(MessageId messageId) =>
        _readerWriter.SendPacket(messageId, _clientToServerEncryption, _clientToServerMac);

    private void SendPacket(MessageId messageId, string param) =>
        _readerWriter.SendPacket(messageId, param, _clientToServerEncryption, _clientToServerMac);

    private SshPacket ReadPacket() => _readerWriter.ReadPacket(_serverToClientEncryption, _serverToClientMac);

    public void Dispose()
    {
        _socket.Dispose();
        _readerWriter.Dispose();
    }

}