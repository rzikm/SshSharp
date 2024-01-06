using System.Buffers;
using System.Buffers.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Packets;
using SshSharp.Utils;

namespace SshSharp.Transport;

internal class SshChannel
{
    private readonly SshConnection _connection;

    private readonly int _channelId;

    public SshChannel(SshConnection connection, int channelId)
    {
        _connection = connection;
        _channelId = channelId;
    }

    public Task ExecuteCommandAsync(string command)
    {
        return Task.CompletedTask;
    }
}

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

    private readonly Dictionary<int, SshChannel> _channels = new();

    public SshConnection(Socket socket)
    {
        _socket = socket;
        _stream = new NetworkStream(socket, ownsSocket: false);
        _readerWriter = new PacketReaderWriter(_stream);
    }

    public static async Task<SshConnection> ConnectAsync(EndPoint endPoint)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(endPoint).ConfigureAwait(false);

        var conn = new SshConnection(socket);
        await conn.DoHandshake().ConfigureAwait(false);
        return conn;
    }

    private async Task DoHandshake()
    {
        // exchange versions
        ServerVersion = await ReadVersionStringAsync().ConfigureAwait(false);
        System.Console.WriteLine($"Server version: {ServerVersion}");

        await _stream.WriteAsync(Constants.VersionBytesCrLf).ConfigureAwait(false);

        await DoKeyExchangeAsync().ConfigureAwait(false);
        await AuthenticateUser().ConfigureAwait(false);
    }

    public async Task ExecuteCommandAsync(string command)
    {
        var channel = new SshChannel(this, 0);

        await SendPacketAsync(new SessionOpenPacket
        {
            InitialWindowSize = 0x100000,
            MaximumPacketSize = 0x4000,
            SenderChannel = 0,
        }).ConfigureAwait(false);

        await ExpectMessageAsync<GlobalRequestPacket>().ConfigureAwait(false);

        var confirmationPacket = await ExpectMessageAsync<ChannelOpenConfirmationPacket>().ConfigureAwait(false);
        Console.WriteLine($"Confirmation: {confirmationPacket.RecipientChannel}, {confirmationPacket.SenderChannel}, {confirmationPacket.InitialWindowSize}, {confirmationPacket.MaximumPacketSize}");
    }

    private async Task AuthenticateUser()
    {
        await SendPacketAsync(new ServiceRequestPacket
        {
            ServiceName = "ssh-userauth"
        }).ConfigureAwait(false);
        await ExpectMessageAsync(MessageId.SSH_MSG_SERVICE_ACCEPT).ConfigureAwait(false);

        SshPublicKey publicKey = SshPublicKey.FromPrivateKeyFile(@"C:\Users\radekzikmund\.ssh\id_rsa");

        var header = new UserAuthRequestHeader
        {
            Username = "EUROPE\\radekzikmund",
            ServiceName = "ssh-connection",
        };

        bool authenticated = false;

        byte[] signatureSrc = ArrayPool<byte>.Shared.Rent(2048);

        foreach (var authAlg in publicKey.GetAlgorithms())
        {
            System.Console.WriteLine($"Attempting auth via: {authAlg.AlgorithmName}");

            var publicKeyData = new UserauthPublicKeyData
            {
                AlgorithmName = authAlg.AlgorithmName,
                PublicKey = authAlg.PublicKey
            };

            await SendPacketAsync(header, publicKeyData).ConfigureAwait(false);

            bool CheckForReplyPacket(IPublicKeyAuthAlgorithm authAlg, out UserauthPublicKeyOkPacket packet)
            {
                var replyPacket = ReadPacket();
                if (replyPacket.MessageId == MessageId.SSH_MSG_USERAUTH_FAILURE)
                {
                    Console.WriteLine($"Rejected: {authAlg.AlgorithmName}");

                    var failurePacket = replyPacket.ParsePayload<UserauthFailurePacket>();
                    packet = default;
                    return false;
                }

                packet = replyPacket.ParsePayload<UserauthPublicKeyOkPacket>();
                if (packet.AlgorithmName != publicKeyData.AlgorithmName)
                {
                    throw new Exception($"Server accepted different algorithm: {packet.AlgorithmName}.");
                }
                if (!packet.PublicKey.AsSpan().SequenceEqual(publicKeyData.PublicKey))
                {
                    throw new Exception($"Server accepted different public key.");
                }
                Console.WriteLine("Public key accepted, retrying with signature.");
                return true;
            }

            await _readerWriter.WaitForPacketAsync(_serverToClientEncryption, _serverToClientMac).ConfigureAwait(false);
            if (!CheckForReplyPacket(authAlg, out var packet))
            {
                continue;
            }

            // temporarily put empty array in signature to force TRUE in the "has signature" field for signature computation
            publicKeyData.Signature = Array.Empty<byte>();

            static byte[] WriteSignature(byte[] workspace, byte[] sessionId, in UserAuthRequestHeader header, in UserauthPublicKeyData publicKeyData, IPublicKeyAuthAlgorithm authAlg)
            {
                SpanWriter writer = new(workspace);
                writer.WriteString(sessionId);
                UserAuthRequestHeader.Write(ref writer, header);
                UserauthPublicKeyData.Write(ref writer, publicKeyData);
                return authAlg.GetSignature(workspace.AsSpan(0, workspace.Length - writer.RemainingBytes - 4));
            }

            publicKeyData.Signature = WriteSignature(signatureSrc, _sessionId, header, publicKeyData, authAlg);

            await SendPacketAsync(header, publicKeyData).ConfigureAwait(false);
            await ExpectMessageAsync(MessageId.SSH_MSG_USERAUTH_SUCCESS).ConfigureAwait(false);
            authenticated = true;
            break;
        }

        ArrayPool<byte>.Shared.Return(signatureSrc);

        if (authenticated)
        {
            Console.WriteLine("User auth successful");
        }
    }

    private async Task DoKeyExchangeAsync()
    {
        var serverKexPacket = await ExpectMessageAsync<KeyExchangeInitPacket>().ConfigureAwait(false);

        var clientKexPacket = new KeyExchangeInitPacket()
        {
            Cookie = (UInt128)Random.Shared.NextInt64() + ((UInt128)Random.Shared.NextInt64()) << 64,
            KeyExchangeAlgorithms = new List<string> { "curve25519-sha256" },
            ServerHostKeyAlgorithms = new List<string> { "rsa-sha2-512" },
            EncryptionAlgorithmsClientToServer = new List<string> { "aes256-ctr" },
            EncryptionAlgorithmsServerToClient = new List<string> { "aes256-ctr" },
            MacAlgorithmsClientToServer = new List<string> { "hmac-sha2-256" },
            MacAlgorithmsServerToClient = new List<string> { "hmac-sha2-256" },
            CompressionAlgorithmsClientToServer = new List<string> { "none" },
            CompressionAlgorithmsServerToClient = new List<string> { "none" },
            LanguagesClientToServer = new List<string> { },
            LanguagesServerToClient = new List<string> { },
            FirstKexPacketFollows = false,
            Reserved = 0,
        };

        _parameters = SshConnectionParameters.FromKeyExchangeInitPacket(serverKexPacket, clientKexPacket);
        _keyExchange = KeyExchange.Create(_parameters.KeyExchangeAlgorithm);

        await SendPacketAsync(clientKexPacket).ConfigureAwait(false);

        // send initial key exchange packet
        await SendPacketAsync(new KeyExchangeEcdhInitPacket
        {
            ClientEphemeralPublicKey = _keyExchange.EphemeralPublicKey,
        }).ConfigureAwait(false);

        var serverKexReply = await ExpectMessageAsync<KeyExchangeEcdhReplyPacket>().ConfigureAwait(false);
        // DebugHelpers.DumpKeyExchangeReplyPacket(serverKexReply);

        _keyExchange.DeriveSharedSecret(serverKexReply.ServerEphemeralPublicKey);
        var exchangeHash = _keyExchange.GetExchangeHash(Encoding.UTF8.GetBytes(ServerVersion), Constants.VersionBytes, clientKexPacket, serverKexPacket, serverKexReply);

        _sessionId ??= exchangeHash;

        _hostKey = HostKeyAlgorithm.CreateFromWireData(serverKexReply.HostKey);

        if (!_hostKey.VerifyExchangeHashSignature(exchangeHash, serverKexReply.ExchangeHashSignature))
        {
            throw new Exception("Failed to verify exchange signature.");
        }

        await SendPacketAsync(MessageId.SSH_MSG_NEWKEYS).ConfigureAwait(false);
        await ExpectMessageAsync(MessageId.SSH_MSG_NEWKEYS).ConfigureAwait(false);
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

    private async ValueTask<T> ExpectMessageAsync<T>() where T : IPacketPayload<T>
    {
        await _readerWriter.WaitForPacketAsync(_serverToClientEncryption, _serverToClientMac).ConfigureAwait(false);
        return ExpectMessageCore();

        T ExpectMessageCore()
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
    }

    private async ValueTask ExpectMessageAsync(MessageId messageId)
    {
        await _readerWriter.WaitForPacketAsync(_serverToClientEncryption, _serverToClientMac).ConfigureAwait(false);
        ExpectMessageCore();

        void ExpectMessageCore()
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
    }

    private async Task<string> ReadVersionStringAsync()
    {
        return Encoding.UTF8.GetString((await _readerWriter.ReadVersionStringAsync().ConfigureAwait(false)).Span);
    }

    private ValueTask SendPacketAsync<TPacket>(in TPacket packet) where TPacket : IPacketPayload<TPacket> =>
        _readerWriter.SendPacketAsync(packet, _clientToServerEncryption, _clientToServerMac);

    private ValueTask SendPacketAsync<TAuth>(in UserAuthRequestHeader header, in TAuth auth) where TAuth : IUserauthMethod<TAuth> =>
        _readerWriter.SendPacketAsync(header, auth, _clientToServerEncryption, _clientToServerMac);

    private ValueTask SendPacketAsync(MessageId messageId) =>
        _readerWriter.SendPacketAsync(messageId, _clientToServerEncryption, _clientToServerMac);

    private ValueTask SendPacketAsync(MessageId messageId, string param) =>
        _readerWriter.SendPacketAsync(messageId, param, _clientToServerEncryption, _clientToServerMac);

    private SshPacket ReadPacket() => _readerWriter.ReadPacket(_serverToClientEncryption, _serverToClientMac);

    public void Dispose()
    {
        _socket.Dispose();
        _readerWriter.Dispose();
    }

}