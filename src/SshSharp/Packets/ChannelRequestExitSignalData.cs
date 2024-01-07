using SshSharp.Utils;

namespace SshSharp.Packets;

internal struct ChannelRequestExitSignalData : IPayload<ChannelRequestExitSignalData>
{
    public int WireLength => GetWireLength();

    public string Signal { get; set; }
    public bool CoreDumped { get; set; }
    public string ErrorMessage { get; set; }
    public string LanguageTag { get; set; }

    private int GetWireLength()
    {
        var length = 0;

        return length;
    }

    public static bool TryRead(ref SpanReader reader, out ChannelRequestExitSignalData payload)
    {
        if (!reader.TryReadString(out var signal) ||
            !reader.TryReadByte(out var coreDumped) ||
            !reader.TryReadString(out var errorMessage) ||
            !reader.TryReadString(out var languageTag))
        {
            payload = default;
            return false;
        }

        payload = new ChannelRequestExitSignalData()
        {
            Signal = signal,
            CoreDumped = coreDumped == 1,
            ErrorMessage = errorMessage,
            LanguageTag = languageTag,
        };
        return true;
    }

    public static void Write(ref SpanWriter writer, in ChannelRequestExitSignalData payload)
    {
        writer.WriteString(payload.Signal);
        writer.WriteBoolean(payload.CoreDumped);
        writer.WriteString(payload.ErrorMessage);
        writer.WriteString(payload.LanguageTag);
    }
}