using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Text;
using SshSharp.Crypto;
using SshSharp.Packets;
using SshSharp.Utils;

namespace SshSharp.Transport;

public class SshConnection : IDisposable
{
    private bool _disposed;

    private Exception? _sentinel;

    public string ServerVersion { get; private set; } = null!;

    private readonly Socket _socket;

    private readonly NetworkStream _stream;

    private readonly PacketReaderWriter _readerWriter;

    private byte[] _sessionId = null!;
    private byte[] _exchangeHash = null!;

    private SshConnectionParameters _parameters = null!;

    private KeyExchange _keyExchange = null!;

    private HostKeyAlgorithm _hostKey = null!;

    private EncryptionAlgorithm _clientToServerEncryption = NullEncryptionAlgorithm.Instance;

    private EncryptionAlgorithm _serverToClientEncryption = NullEncryptionAlgorithm.Instance;

    private MacAlgorithm _clientToServerMac = new NullMacAlgorithm();

    private MacAlgorithm _serverToClientMac = new NullMacAlgorithm();

    private int _channelCount;
    private readonly ConcurrentDictionary<int, SshChannel> _channels = new();

    private object SendLock => _clientToServerMac;

    private Task _receiveLoopTask = null!;

    private KeyExchangeInitPacket _serverKexPacket;

    private KeyExchangeInitPacket _clientKexPacket;

    // TODO: find a better way to wait for replies
    private readonly TaskCompletionSource _handshakeCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource<(bool, UserauthPublicKeyOkPacket)> _userAuthPublicKey = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _serviceAccept = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _userAuthSuccess = new(TaskCreationOptions.RunContinuationsAsynchronously);

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
        Log.Info($"Server version: {ServerVersion}");

        await _stream.WriteAsync(Constants.VersionBytesCrLf).ConfigureAwait(false);

        await KickOffKeyExchangeAsync().ConfigureAwait(false);
        _receiveLoopTask = Task.Run(ReceiveLoop);

        await _handshakeCompletionSource.Task.ConfigureAwait(false);
        await AuthenticateUser().ConfigureAwait(false);
    }

    public async Task<SshChannel> ExecuteShellAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var channel = new SshChannel(this);

        var packet = new SessionOpenPacket
        {
            InitialWindowSize = 0x100000,
            MaximumPacketSize = 0x4000,
            SenderChannel = Interlocked.Increment(ref _channelCount) - 1,
        };

        _channels.TryAdd(packet.SenderChannel, channel);

        await SendPacketAsync(packet).ConfigureAwait(false);
        await channel.WaitToOpen().ConfigureAwait(false);

        return channel;
    }

    private async Task AuthenticateUser()
    {
        await SendPacketAsync(new ServiceRequestPacket
        {
            ServiceName = "ssh-userauth"
        }).ConfigureAwait(false);

        await _serviceAccept.Task.ConfigureAwait(false);

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
            Log.Info($"Attempting auth via: {authAlg.AlgorithmName}");

            var publicKeyData = new UserauthPublicKeyData
            {
                AlgorithmName = authAlg.AlgorithmName,
                PublicKey = authAlg.PublicKey
            };

            await SendPacketAsync(header, publicKeyData).ConfigureAwait(false);
            var (success, packet) = await _userAuthPublicKey.Task.ConfigureAwait(false);
            if (!success)
            {
                Log.Info($"Rejected: {authAlg.AlgorithmName}");
                _userAuthPublicKey = new();
                continue;
            }

            if (packet.AlgorithmName != publicKeyData.AlgorithmName)
            {
                throw new Exception($"Server accepted different algorithm: {packet.AlgorithmName}.");
            }
            if (!packet.PublicKey.AsSpan().SequenceEqual(publicKeyData.PublicKey))
            {
                throw new Exception($"Server accepted different public key.");
            }
            Log.Info("Public key accepted, retrying with signature.");

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
            await _userAuthSuccess.Task.ConfigureAwait(false);
            authenticated = true;
            break;
        }

        ArrayPool<byte>.Shared.Return(signatureSrc);

        if (authenticated)
        {
            Log.Info("User auth successful");
        }
    }

    private ValueTask KickOffKeyExchangeAsync()
    {
        _clientKexPacket = new KeyExchangeInitPacket()
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

        return SendPacketAsync(_clientKexPacket);
    }

    private async Task ReceiveLoop()
    {
        do
        {
            await _readerWriter.WaitForPacketAsync(_serverToClientEncryption, _serverToClientMac).ConfigureAwait(false);
        } while (await ProcessNextPacket().ConfigureAwait(false));
    }

    private async ValueTask<bool> OnKeyExchangeInitPacket(KeyExchangeInitPacket serverKexPacket)
    {
        _serverKexPacket = serverKexPacket;
        _parameters = SshConnectionParameters.FromKeyExchangeInitPacket(serverKexPacket, _clientKexPacket);
        _keyExchange = KeyExchange.Create(_parameters.KeyExchangeAlgorithm);

        // send initial key exchange packet
        await SendPacketAsync(new KeyExchangeEcdhInitPacket
        {
            ClientEphemeralPublicKey = _keyExchange.EphemeralPublicKey,
        }).ConfigureAwait(false);

        return true;
    }

    private async ValueTask<bool> OnKeyExchangeEcdhReplyPacket(KeyExchangeEcdhReplyPacket kexReplyPacket)
    {
        _keyExchange.DeriveSharedSecret(kexReplyPacket.ServerEphemeralPublicKey);
        var exchangeHash = _keyExchange.GetExchangeHash(Encoding.UTF8.GetBytes(ServerVersion), Constants.VersionBytes, _clientKexPacket, _serverKexPacket, kexReplyPacket);

        _sessionId ??= exchangeHash;
        _exchangeHash = exchangeHash;

        _hostKey = HostKeyAlgorithm.CreateFromWireData(kexReplyPacket.HostKey);

        if (!_hostKey.VerifyExchangeHashSignature(exchangeHash, kexReplyPacket.ExchangeHashSignature))
        {
            throw new Exception("Failed to verify exchange signature.");
        }

        await SendPacketAsync(MessageId.SSH_MSG_NEWKEYS).ConfigureAwait(false);
        DeriveClientToServerEncryptionKeys();

        return true;
    }

    private ValueTask<bool> ProcessNextPacket()
    {
        var packet = _readerWriter.ReadPacket(_serverToClientEncryption, _serverToClientMac);
        Log.Debug($"Received packet: {packet.MessageId}");
        switch (packet.MessageId)
        {
            case MessageId.SSH_MSG_KEXINIT:
                if (packet.TryParsePayload(out KeyExchangeInitPacket kexInitPacket, out _))
                    return OnKeyExchangeInitPacket(kexInitPacket);
                break;

            case MessageId.SSH_MSG_KEXDH_REPLY:
                if (packet.TryParsePayload(out KeyExchangeEcdhReplyPacket kexReplyPacket, out _))
                    return OnKeyExchangeEcdhReplyPacket(kexReplyPacket);
                break;

            case MessageId.SSH_MSG_NEWKEYS:
                DeriveServerToClientEncryptionKeys();
                _handshakeCompletionSource.TrySetResult();
                return ValueTask.FromResult(true);

            case MessageId.SSH_MSG_SERVICE_ACCEPT:
                _serviceAccept.TrySetResult();
                return ValueTask.FromResult(true);

            case MessageId.SSH_MSG_USERAUTH_FAILURE:
                _userAuthPublicKey.TrySetResult((false, default));
                return ValueTask.FromResult(true);

            case MessageId.SSH_MSG_USERAUTH_PK_OK:
                if (packet.TryParsePayload(out UserauthPublicKeyOkPacket userAuthPublicKeyOkPacket, out _))
                {
                    _userAuthPublicKey.TrySetResult((true, userAuthPublicKeyOkPacket));
                    return ValueTask.FromResult(true);
                }
                break;

            case MessageId.SSH_MSG_USERAUTH_SUCCESS:
                _userAuthSuccess.TrySetResult();
                return ValueTask.FromResult(true);

            case MessageId.SSH_MSG_GLOBAL_REQUEST:
                if (packet.TryParsePayload(out GlobalRequestPacket globalRequestPacket, out _))
                {
                    Log.Info($"Global request: {globalRequestPacket.RequestName}, want reply: {globalRequestPacket.WantReply}");
                    return ValueTask.FromResult(true);
                }
                break;

            case MessageId id when id >= MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION && id <= MessageId.SSH_MSG_CHANNEL_FAILURE:
                // first byte is messageId, then is uint32 recipientChannel id
                if (DataHelper.TryReadPrimitive(packet.Payload.Slice(1), out int channelId, out _))
                {
                    if (_channels.TryGetValue(channelId, out var channel))
                    {
                        return channel.ProcessPacketAsync(packet);
                    }

                    Log.Info($"Unknown channel: {channelId}");
                }
                break;

            default:
                Log.Info($"Unknown Message: {packet.MessageId}");
                _sentinel = ExceptionDispatchInfo.SetCurrentStackTrace(new Exception($"Unexpected packet: {packet.MessageId}"));
                break;
        }

        Log.Info($"Failed to process message: {packet.MessageId}");
        return ValueTask.FromResult(false);
    }

    //
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
    //

    private void DeriveClientToServerEncryptionKeys()
    {
        Log.Info("Deriving client to server encryption keys.");

        byte[] HashHelper(char c, int len) => KeyGenerationHelpers.DeriveSessionKey(_keyExchange.SharedSecret, _exchangeHash, c, _sessionId, _keyExchange, len);

        _clientToServerEncryption = EncryptionAlgorithm.Create(_parameters.EncryptionAlgorithmClientToServer,
            l => HashHelper('A', l),
            l => HashHelper('C', l));

        _clientToServerMac = MacAlgorithm.Create(_parameters.MacAlgorithmClientToServer, _clientToServerMac.SequenceNumber, l => HashHelper('E', l));
    }

    private void DeriveServerToClientEncryptionKeys()
    {
        Log.Info("Deriving server to client encryption keys.");

        byte[] HashHelper(char c, int len) => KeyGenerationHelpers.DeriveSessionKey(_keyExchange.SharedSecret, _exchangeHash, c, _sessionId, _keyExchange, len);

        _serverToClientEncryption = EncryptionAlgorithm.Create(_parameters.EncryptionAlgorithmServerToClient,
            l => HashHelper('B', l),
            l => HashHelper('D', l));

        _serverToClientMac = MacAlgorithm.Create(_parameters.MacAlgorithmClientToServer, _clientToServerMac.SequenceNumber, l => HashHelper('F', l));
    }

    private async Task<string> ReadVersionStringAsync()
    {
        return Encoding.UTF8.GetString((await _readerWriter.ReadVersionStringAsync().ConfigureAwait(false)).Span);
    }

    //
    // All send operations need to be serialized because of the encryption and MAC algorithms.
    //

    internal ValueTask SendPacketAsync<TPacket>(in TPacket packet) where TPacket : IPacketPayload<TPacket>
    {
        lock (SendLock)
        {
            SpanWriter writer = _readerWriter.InitPayload();
            TPacket.Write(ref writer, packet);
            return _readerWriter.FinalizeAndSendAsync(writer, _clientToServerEncryption, _clientToServerMac);
        }
    }

    internal ValueTask SendPacketAsync<TPacket, TData>(in TPacket header, in TData data) where TPacket : IPacketPayload<TPacket> where TData : IPayload<TData>
    {
        lock (SendLock)
        {
            SpanWriter writer = _readerWriter.InitPayload();
            TPacket.Write(ref writer, header);
            TData.Write(ref writer, data);
            return _readerWriter.FinalizeAndSendAsync(writer, _clientToServerEncryption, _clientToServerMac);
        }
    }

    internal ValueTask SendPacketAsync(MessageId messageId)
    {
        lock (SendLock)
        {
            SpanWriter writer = _readerWriter.InitPayload();
            writer.WriteByte((byte)messageId);
            return _readerWriter.FinalizeAndSendAsync(writer, _clientToServerEncryption, _clientToServerMac);
        }
    }

    public void Dispose()
    {
        _socket.Dispose();
        _readerWriter.Dispose();
        _disposed = true;
    }

}