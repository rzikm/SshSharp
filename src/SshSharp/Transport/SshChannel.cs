using System.IO.Pipelines;
using System.Threading.Channels;
using SshSharp.Packets;
using SshSharp.Utils;

namespace SshSharp.Transport;

public class Limiter
{
    private readonly int _limit;

    private int _count;

    public Limiter(int limit)
    {
        _limit = limit;
    }

    public bool TryAcquire()
    {
        if (_count < _limit)
        {
            _count++;
            return true;
        }

        return false;
    }

    public void Release()
    {
        _count--;
    }
}

public class SshChannel
{
    private readonly SshConnection _connection;

    private readonly TaskCompletionSource _opened = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private ChannelOpenConfirmationPacket _confirmationPacket;

    // private int _receiveWindowSize;

    private int _sendWindowSize;

    private Pipe _receivePipe = new();

    private Pipe _sendPipe = new();

    private Task _sendTask;

    public SshChannel(SshConnection connection)
    {
        _connection = connection;
        _sendTask = Task.Run(() => SendTask());
    }

    private async Task SendTask()
    {
        var reader = _sendPipe.Reader;
        while (true)
        {
            var result = await reader.ReadAsync().ConfigureAwait(false);
            var maxSend = Math.Min(_confirmationPacket.MaximumPacketSize, _sendWindowSize);

            foreach (var buffer in result.Buffer)
            {
                var len = Math.Min(buffer.Length, maxSend);

                Log.Info($"Sending {len} bytes");
                await _connection.SendPacketAsync(new ChannelDataPacket()
                {
                    RecipientChannel = _confirmationPacket.SenderChannel,
                    Data = buffer.Slice(0, len).ToArray()
                }).ConfigureAwait(false);

                Interlocked.Add(ref _sendWindowSize, -len);
            }

            reader.AdvanceTo(result.Buffer.End);

            if (result.IsCompleted)
            {
                break;
            }
        }

        await reader.CompleteAsync().ConfigureAwait(false);
    }

    public Stream GetOutputStream()
    {
        return _receivePipe.Reader.AsStream();
    }

    public Stream GetInputStream()
    {
        return _sendPipe.Writer.AsStream();
    }

    internal ValueTask<bool> ProcessExitStatus(in ChannelRequestHeader header, int status)
    {
        Log.Info($"Process exitted: {status}");
        return ValueTask.FromResult(true);
    }

    internal ValueTask<bool> ProcessExitSignal(in ChannelRequestHeader header, ChannelRequestExitSignalData exitSignalData)
    {
        Log.Info($"Process receivedSignal: {exitSignalData.Signal}, coreDumped: {exitSignalData.CoreDumped}, errorMessage: {exitSignalData.ErrorMessage}, languageTag: {exitSignalData.LanguageTag}");
        return ValueTask.FromResult(true);
    }

    internal ValueTask<bool> ProcessPacketAsync(in SshPacket packet)
    {
        switch (packet.MessageId)
        {
            case MessageId.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                if (packet.TryParsePayload(out ChannelOpenConfirmationPacket payload, out _))
                {
                    return OnOpened(payload);
                }
                break;

            case MessageId.SSH_MSG_CHANNEL_DATA:
                if (packet.TryParsePayload(out ChannelDataPacket dataPacket, out _))
                {
                    return OnDataReceived(dataPacket.Data);
                }
                break;

            case MessageId.SSH_MSG_CHANNEL_EXTENDED_DATA:
                if (packet.TryParsePayload(out ChannelExtendedDataPacket extendedDataPacket, out _))
                {
                    return OnDataReceived(extendedDataPacket.Data, extendedDataPacket.DataTypeCode);
                }
                break;

            case MessageId.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                if (packet.TryParsePayload(out ChannelWindowAdjustPacket windowAdjustPacket, out _))
                {
                    return OnWindowAdjust(windowAdjustPacket.BytesToAdd);
                }
                break;

            case MessageId.SSH_MSG_CHANNEL_REQUEST:
                {
                    SpanReader reader = new(packet.Payload);
                    if (!ChannelRequestHeader.TryRead(ref reader, out ChannelRequestHeader header))
                    {
                        break;
                    }

                    switch (header.RequestType)
                    {
                        case "exit-status":
                            if (reader.TryReadUInt32(out uint status))
                            {
                                return ProcessExitStatus(header, (int)status);
                            }
                            break;

                        case "exit-signal":
                            if (ChannelRequestExitSignalData.TryRead(ref reader, out ChannelRequestExitSignalData exitSignalData))
                            {
                                return ProcessExitSignal(header, exitSignalData);
                            }
                            break;

                        default:
                            Log.Info($"Unsupported channel request: {header.RequestType}, want reply: {header.WantReply}");
                            return ValueTask.FromResult(true);
                    }
                }
                break;

            case MessageId.SSH_MSG_CHANNEL_SUCCESS:
                _opened.TrySetResult();
                return ValueTask.FromResult(true);

            case MessageId.SSH_MSG_CHANNEL_EOF:
                return OnEof();

            case MessageId.SSH_MSG_CHANNEL_CLOSE:
                return OnClose();

            default:
                Log.Info($"Unsupported channel message: {packet.MessageId}");
                return ValueTask.FromResult(false);
        }

        Log.Info($"Failed to parse channel message: {packet.MessageId}");
        return ValueTask.FromResult(false);
    }

    internal async ValueTask<bool> OnOpened(ChannelOpenConfirmationPacket confirmationPacket)
    {
        Log.Info($"Channel opened: {confirmationPacket.RecipientChannel}<->{confirmationPacket.SenderChannel}");
        Log.Info($"InitialWindowSize: {confirmationPacket.InitialWindowSize}");
        Log.Info($"MaximumPacketSize: {confirmationPacket.MaximumPacketSize}");

        _confirmationPacket = confirmationPacket;

        await _connection.SendPacketAsync(new ChannelRequestHeader()
        {
            RecipientChannel = confirmationPacket.RecipientChannel,
            RequestType = "shell",
            WantReply = true
        });

        return true;
    }

    internal async ValueTask<bool> OnDataReceived(byte[] data, int? extendedDataTypeCode = null)
    {
        Log.Debug($"Data received: {data.Length} bytes, extendedDataTypeCode: {extendedDataTypeCode}");
        await _receivePipe.Writer.WriteAsync(data).ConfigureAwait(false);
        await _receivePipe.Writer.FlushAsync().ConfigureAwait(false);
        return true;
    }

    internal ValueTask<bool> OnWindowAdjust(int bytesToAdd)
    {
        var newSize = Interlocked.Add(ref _sendWindowSize, bytesToAdd);
        Log.Info($"Window received: +{bytesToAdd} = {newSize}");
        return ValueTask.FromResult(true);
    }

    internal async ValueTask<bool> OnEof()
    {
        Log.Info($"EOF received");
        await _receivePipe.Writer.CompleteAsync().ConfigureAwait(false);
        return true;
    }

    internal ValueTask<bool> OnClose()
    {
        Log.Info($"Close received");
        return ValueTask.FromResult(true);
    }

    internal Task WaitToOpen()
    {
        return _opened.Task;
    }
}
