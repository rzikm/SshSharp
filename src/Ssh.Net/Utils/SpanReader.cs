using System.Diagnostics.CodeAnalysis;

namespace Ssh.Net.Utils;

internal ref struct SpanReader
{
    private ReadOnlySpan<byte> _buffer;

    public int RemainingBytes => _buffer.Length;

    public SpanReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
    }

    public bool TryReadStringAsSpan(out ReadOnlySpan<byte> value)
    {
        var res = DataHelper.TryReadStringAsSpan(_buffer, out value, out var consumed);

        if (res)
        {
            _buffer = _buffer.Slice(consumed);
        }

        return res;
    }

    public bool TryReadString([NotNullWhen(true)] out string? value)
    {
        var res = DataHelper.TryReadString(_buffer, out value, out var consumed);

        if (res)
        {
            _buffer = _buffer.Slice(consumed);
        }

        return res;
    }

    public bool TryReadStringList([NotNullWhen(true)] out List<string>? value)
    {
        var res = DataHelper.TryReadStringList(_buffer, out value, out var consumed);

        if (res)
        {
            _buffer = _buffer.Slice(consumed);
        }

        return res;
    }

    public bool TryReadBoolean(out bool value)
    {
        var res = DataHelper.TryReadBoolean(_buffer, out value, out var consumed);

        if (res)
        {
            _buffer = _buffer.Slice(consumed);
        }

        return res;
    }

    private bool TryReadPrimitive<T>(out T value)
        where T : unmanaged
    {
        var res = DataHelper.TryReadPrimitive(_buffer, out value, out var consumed);

        if (res)
        {
            _buffer = _buffer.Slice(consumed);
        }

        return res;
    }

    public bool TryReadUInt128(out UInt128 value) => TryReadPrimitive(out value);
    public bool TryReadUInt16(out ushort value) => TryReadPrimitive(out value);
    public bool TryReadUInt32(out uint value) => TryReadPrimitive(out value);
    public bool TryReadByte(out byte value) => TryReadPrimitive(out value);

    public bool TryReadRawBytes(int length, out ReadOnlySpan<byte> value)
    {
        if (_buffer.Length < length)
        {
            value = default;
            return false;
        }

        value = _buffer.Slice(0, length);
        _buffer = _buffer.Slice(length);

        return true;
    }
}