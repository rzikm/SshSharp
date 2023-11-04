using System.Buffers.Binary;
using System.Text;

namespace Ssh.Net.Utils;

internal ref struct SpanWriter
{
    private Span<byte> _buffer;

    public int RemainingBytes => _buffer.Length;

    public SpanWriter(Span<byte> buffer)
    {
        _buffer = buffer;
    }

    public void WriteString(string? value)
    {
        if (value == null)
        {
            BinaryPrimitives.WriteUInt32BigEndian(_buffer, 0);
            _buffer = _buffer.Slice(4);
            return;
        }

        var length = Encoding.UTF8.GetByteCount(value);

        BinaryPrimitives.WriteUInt32BigEndian(_buffer, (uint)length);
        Encoding.UTF8.GetBytes(value, _buffer.Slice(4));

        _buffer = _buffer.Slice(4 + length);
    }

    public void WriteStringList(List<string>? value)
    {
        if (value == null)
        {
            BinaryPrimitives.WriteUInt32BigEndian(_buffer, 0);
            _buffer = _buffer.Slice(4);
            return;
        }

        var length = DataHelper.GetStringListWireLength(value) - 4;

        BinaryPrimitives.WriteUInt32BigEndian(_buffer, (uint)length);
        _buffer = _buffer.Slice(4);

        if (value.Count == 0)
        {
            return;
        }

        int written = Encoding.UTF8.GetBytes(value[0], _buffer);
        _buffer = _buffer.Slice(written);

        for (int i = 1; i < value.Count; i++)
        {
            _buffer[0] = (byte)',';
            written = Encoding.UTF8.GetBytes(value[i], _buffer.Slice(1));
            _buffer = _buffer.Slice(written + 1);
        }
    }

    public void WriteByte(byte value)
    {
        _buffer[0] = value;
        _buffer = _buffer.Slice(1);
    }

    public void WriteBoolean(bool value) => WriteByte(value ? (byte)1 : (byte)0);

    private void WritePrimitive<T>(T value)
        where T : unmanaged
    {
        DataHelper.TryWritePrimitive(_buffer, value, out var written);
        _buffer = _buffer.Slice(written);
    }

    public void WriteUInt32(uint value) => WritePrimitive(value);

    public void WriteUInt128(UInt128 value) => WritePrimitive(value);
}