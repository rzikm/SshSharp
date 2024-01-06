using System.Diagnostics;
using System.Net.Sockets;
using SshSharp.Crypto;
using SshSharp.Packets;
using SshSharp.Utils;

namespace SshSharp.Transport;

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

    public async ValueTask WaitForPacketAsync(EncryptionAlgorithm encryption, MacAlgorithm mac, CancellationToken cancellationToken = default)
    {
        if (_lastConsumed > 0)
        {
            // copy leftover to beginning
            _recvBuffer.AsSpan(_lastConsumed, _bytes - _lastConsumed).CopyTo(_recvBuffer);
            _bytes -= _lastConsumed;
            _lastConsumed = 0;
        }

        while (_bytes < encryption.BlockSize)
        {
            _bytes += await _stream.ReadAsync(_recvBuffer.AsMemory(_bytes)).ConfigureAwait(false);
        }

        // decrypt the first block to get the length
        encryption.Decrypt(_recvBuffer.AsSpan(0, encryption.BlockSize));
        int totalLength = SshPacket.GetExpectedLength(_recvBuffer, mac.MacSize);

        while (_bytes < totalLength)
        {
            _bytes += await _stream.ReadAsync(_recvBuffer.AsMemory(_bytes)).ConfigureAwait(false);
        }

        // decrypt the rest
        encryption.Decrypt(_recvBuffer.AsSpan(encryption.BlockSize, totalLength - encryption.BlockSize - mac.MacSize));
    }

    public SshPacket ReadPacket() => ReadPacket(NullEncryptionAlgorithm.Instance, NullMacAlgorithm.Instance);

    public SshPacket ReadPacket(EncryptionAlgorithm encryption, MacAlgorithm mac)
    {
        SshPacket packet;

        int totalLength = SshPacket.GetExpectedLength(_recvBuffer, mac.MacSize);
        Debug.Assert(totalLength <= _bytes && _bytes > 0, "Packet is not fully received.");

        if (!SshPacket.TryRead(_recvBuffer.AsSpan(0, _bytes), mac.MacSize, out packet, out int consumed))
        {
            throw new Exception("Corrupted packet.");
        }

        if (!mac.Verify(_recvBuffer.AsSpan(0, totalLength - packet.Mac.Length), packet.Mac))
        {
            throw new Exception("Invalid mac.");
        }

        _lastConsumed = consumed;
        return packet;
    }

    public async Task<ReadOnlyMemory<byte>> ReadVersionStringAsync()
    {
        int index;
        do
        {
            _bytes += await _stream.ReadAsync(_recvBuffer.AsMemory(_bytes)).ConfigureAwait(false);
            index = _recvBuffer.AsSpan(0, _bytes).IndexOf("\r\n"u8);
        } while (index == -1 && _bytes < 256);

        if (index == -1)
        {
            throw new Exception("Failed to read version string.");
        }

        _lastConsumed = index + 2;
        return _recvBuffer.AsMemory(0, index);
    }

    public ValueTask SendPacketAsync<TAuth>(in UserAuthRequestHeader header, in TAuth auth, EncryptionAlgorithm encryption, MacAlgorithm mac) where TAuth : IUserauthMethod<TAuth>
    {
        int written = PacketHelpers.WritePayload(_sendBuffer, header, auth, encryption, mac);
        return _stream.WriteAsync(_sendBuffer.AsMemory(0, written));
    }

    public ValueTask SendPacketAsync<T>(in T packet, EncryptionAlgorithm encryption, MacAlgorithm mac) where T : IPacketPayload<T>
    {
        int written = PacketHelpers.WritePayload(_sendBuffer, packet, encryption, mac);
        return _stream.WriteAsync(_sendBuffer.AsMemory(0, written));
    }

    public ValueTask SendPacketAsync(MessageId messageId, string param) => SendPacketAsync(messageId, param, NullEncryptionAlgorithm.Instance, NullMacAlgorithm.Instance);

    public ValueTask SendPacketAsync(MessageId messageId, string param, EncryptionAlgorithm encryption, MacAlgorithm mac)
    {
        Span<byte> buffer = stackalloc byte[DataHelper.GetStringWireLength(param) + 1];
        SpanWriter writer = new(buffer);
        writer.WriteByte((byte)messageId);
        writer.WriteString(param);

        int written = PacketHelpers.WritePayload(_sendBuffer, buffer, encryption, mac);
        return _stream.WriteAsync(_sendBuffer.AsMemory(0, written));
    }

    public ValueTask SendPacketAsync(MessageId messageId) => SendPacketAsync(messageId, NullEncryptionAlgorithm.Instance, NullMacAlgorithm.Instance);

    public ValueTask SendPacketAsync(MessageId messageId, EncryptionAlgorithm encryption, MacAlgorithm mac)
    {
        Span<byte> buffer = [(byte)messageId];
        int written = PacketHelpers.WritePayload(_sendBuffer, buffer, encryption, mac);
        return _stream.WriteAsync(_sendBuffer.AsMemory(0, written));
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