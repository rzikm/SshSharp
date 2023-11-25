using System.Diagnostics.CodeAnalysis;
using Ssh.Net.Utils;

namespace Ssh.Net;

internal interface IPacketPayload<T> : IPayload<T> where T : IPacketPayload<T>
{
    static abstract MessageId MessageId { get; }
}

internal interface IUserauthMethod<T> : IPayload<T> where T : IUserauthMethod<T>
{
    static abstract string Name { get; }
}

internal interface IPayload<T> where T : IPayload<T>
{
    static abstract bool TryRead(ref SpanReader reader, out T payload);
    public static bool TryRead(ReadOnlySpan<byte> buffer, [NotNullWhen(true)] out T? payload, out int consumed)
    {
        payload = default;
        SpanReader reader = new(buffer);

        bool res = T.TryRead(ref reader, out payload);
        consumed = buffer.Length - reader.RemainingBytes;
        return res;
    }

    static abstract void Write(ref SpanWriter writer, in T payload);
    public static int Write(Span<byte> destination, in T payload)
    {
        if (destination.Length < payload.WireLength)
        {
            throw new ArgumentException("Destination buffer is too small.", nameof(destination));
        }

        var writer = new SpanWriter(destination);

        T.Write(ref writer, in payload);

        return destination.Length - writer.RemainingBytes;
    }

    int WireLength { get; }
}