using System.Net.Sockets;
using Ssh.Net.Packets;
using Ssh.Net.Utils;

namespace Ssh.Net.Transport;

internal class PacketReaderWriter : IDisposable
{
    private readonly Stream _stream;

    private readonly byte[] _recvBuffer = new byte[64 * 1024];
    private int _bytes;
    private int _lastConsumed;

    private readonly byte[] _sendBuffer = new byte[64 * 1024];
    private bool _disposed;

    public PacketReaderWriter(Stream stream)
    {
        _stream = stream;
    }

    public SshPacket ReadPacket()
    {
        SshPacket packet;

        if (_lastConsumed > 0)
        {
            // copy leftover to beginning
            _recvBuffer.AsSpan(_lastConsumed, _bytes - _lastConsumed).CopyTo(_recvBuffer);
            _bytes -= _lastConsumed;
            _lastConsumed = 0;
        }

        int consumed;

        while (!SshPacket.TryRead(_recvBuffer.AsSpan(0, _bytes), 0, out packet, out consumed))
        {
            if (consumed <= _bytes)
            {
                throw new Exception("Corrupted packet.");
            }

            while (_bytes < consumed)
            {
                _bytes += _stream.Read(_recvBuffer.AsSpan(_bytes));
            }
        }

        _lastConsumed = consumed;
        return packet;
    }

    public ReadOnlySpan<byte> ReadVersionString()
    {
        int index;
        do
        {
            _bytes += _stream.Read(_recvBuffer.AsSpan(_bytes));
            index = _recvBuffer.AsSpan(0, _bytes).IndexOf("\r\n"u8);
        } while (index == -1 && _bytes < 256);

        if (index == -1)
        {
            throw new Exception("Failed to read version string.");
        }

        _lastConsumed = index + 2;
        return _recvBuffer.AsSpan(0, index);
    }

    public void SendPacket<T>(in T packet) where T : IPacketPayload<T>
    {
        int written = PacketHelpers.WritePayload(_sendBuffer, packet);
        _stream.Write(_sendBuffer.AsSpan(0, written));
    }

    public void SendPacket(MessageId messageId, string param)
    {
        Span<byte> buffer = stackalloc byte[DataHelper.GetStringWireLength(param) + 1];
        SpanWriter writer = new(buffer);
        writer.WriteByte((byte)messageId);
        writer.WriteString(param);

        int written = PacketHelpers.WritePayload(_sendBuffer, buffer);
        _stream.Write(_sendBuffer.AsSpan(0, written));
    }

    public void SendPacket(MessageId messageId)
    {
        Span<byte> buffer = [(byte)messageId];
        int written = PacketHelpers.WritePayload(_sendBuffer, buffer);
        _stream.Write(_sendBuffer.AsSpan(0, written));
    }

    public void WritePacket(in SshPacket packet)
    {
        SshPacket.Write(_sendBuffer, packet);
        _stream.Write(_sendBuffer.AsSpan(0, packet.WireLength));
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _stream.Dispose();
            }

            _disposed = true;
        }
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
    }
}