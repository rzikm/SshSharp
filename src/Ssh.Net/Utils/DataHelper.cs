using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Ssh.Net.Utils;

internal static class DataHelper
{
    internal static int GetStringWireLength(string value)
    {
        return 4 + Encoding.UTF8.GetByteCount(value);
    }

    internal static int GetStringWireLength(ReadOnlySpan<byte> value)
    {
        return 4 + value.Length;
    }

    internal static int GetStringListWireLength(List<string> values)
    {
        var length = 4;
        length += values.Count > 0 ? values.Count - 1 : 0;

        foreach (var value in values)
        {
            length += Encoding.UTF8.GetByteCount(value);
        }

        return length;
    }

    internal static bool TryReadStringAsSpan(ReadOnlySpan<byte> buffer, out ReadOnlySpan<byte> value, out int consumed)
    {
        value = default;
        consumed = 4;

        if (buffer.Length < 4)
        {
            return false;
        }

        var length = BinaryPrimitives.ReadUInt32BigEndian(buffer);
        consumed = 4 + (int)length;

        if (length < 0)
        {
            throw new ArgumentException("Corrupted string length.");
        }

        if (buffer.Length < length + 4)
        {
            // too small, need more data
            return false;
        }

        value = buffer.Slice(4, (int)length);
        return true;
    }

    internal static bool TryReadString(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out string? value, out int consumed)
    {
        value = default;

        if (TryReadStringAsSpan(buffer, out var span, out consumed))
        {
            value = Encoding.UTF8.GetString(span);
            return true;
        }

        return false;
    }

    internal static bool TryReadStringList(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out List<string>? value, out int consumed)
    {
        value = default;

        if (TryReadStringAsSpan(buffer, out var span, out consumed))
        {
            value = new List<string>();

            int index;
            while ((index = span.IndexOf((byte)',')) != -1)
            {
                value.Add(Encoding.UTF8.GetString(span.Slice(0, index)));
                span = span.Slice(index + 1);
            }

            // add leftover
            if (span.Length > 0)
            {
                value.Add(Encoding.UTF8.GetString(span));
            }

            return true;
        }

        return false;
    }

    internal static bool TryReadPrimitive<T>(ReadOnlySpan<byte> buffer, out T value, out int consumed)
        where T : unmanaged
    {
        value = default;
        consumed = Unsafe.SizeOf<T>();

        if (buffer.Length < consumed)
        {
            return false;
        }

        if (BitConverter.IsLittleEndian)
        {
            Span<byte> helpBuffer = stackalloc byte[consumed];

            buffer.Slice(0, consumed).CopyTo(helpBuffer);
            helpBuffer.Reverse();

            value = MemoryMarshal.Read<T>(helpBuffer);
        }
        else
        {
            value = MemoryMarshal.Read<T>(buffer);
        }
        return true;
    }

    internal static bool TryWritePrimitive<T>(Span<byte> buffer, T value, out int written)
        where T : unmanaged
    {
        written = Unsafe.SizeOf<T>();
        if (buffer.Length < written)
        {
            return false;
        }

        if (BitConverter.IsLittleEndian)
        {
            Span<byte> helpBuffer = stackalloc byte[Unsafe.SizeOf<T>()];

            MemoryMarshal.Write(helpBuffer, value);
            helpBuffer.Reverse();

            helpBuffer.CopyTo(buffer);
        }
        else
        {
            MemoryMarshal.Write(buffer, value);
        }

        return true;
    }

    internal static bool TryReadBoolean(ReadOnlySpan<byte> buffer, out bool value, out int consumed)
    {
        value = default;
        consumed = 1;

        if (buffer.Length < 1)
        {
            return false;
        }

        value = buffer[0] != 0;
        return true;
    }

    internal static bool TryReadUInt16(ReadOnlySpan<byte> buffer, out ushort value, out int consumed)
    {
        return TryReadPrimitive(buffer, out value, out consumed);
    }
}