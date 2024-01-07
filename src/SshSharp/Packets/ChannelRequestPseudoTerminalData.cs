using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelRequestPseudoTerminalData : IPayload<ChannelRequestPseudoTerminalData>
{
    public int WireLength => GetWireLength();

    public string TerminalType { get; set; }
    public int TerminalWidthCharacters { get; set; }
    public int TerminalHeightRows { get; set; }
    public int TerminalWidthPixels { get; set; }
    public int TerminalHeightPixels { get; set; }
    public byte[] TerminalModes { get; set; }

    private int GetWireLength()
    {
        var length = 0;

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelRequestPseudoTerminalData payload)
    {
        if (!reader.TryReadString(out var terminalType) ||
            !reader.TryReadUInt32(out var terminalWidthCharacters) ||
            !reader.TryReadUInt32(out var terminalHeightRows) ||
            !reader.TryReadUInt32(out var terminalWidthPixels) ||
            !reader.TryReadUInt32(out var terminalHeightPixels) ||
            !reader.TryReadStringAsSpan(out var terminalModes))
        {
            payload = default;
            return false;
        }

        payload = new ChannelRequestPseudoTerminalData()
        {
            TerminalType = terminalType,
            TerminalWidthCharacters = (int)terminalWidthCharacters,
            TerminalHeightRows = (int)terminalHeightRows,
            TerminalWidthPixels = (int)terminalWidthPixels,
            TerminalHeightPixels = (int)terminalHeightPixels,
            TerminalModes = terminalModes.ToArray(),
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelRequestPseudoTerminalData payload)
    {
        writer.WriteString(payload.TerminalType);
        writer.WriteUInt32((uint)payload.TerminalWidthCharacters);
        writer.WriteUInt32((uint)payload.TerminalHeightRows);
        writer.WriteUInt32((uint)payload.TerminalWidthPixels);
        writer.WriteUInt32((uint)payload.TerminalHeightPixels);
        writer.WriteString(payload.TerminalModes);
    }
}