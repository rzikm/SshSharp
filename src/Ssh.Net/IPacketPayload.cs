namespace Ssh.Net;

internal interface IPacketPayload<T>
{
    static abstract bool TryRead(ReadOnlySpan<byte> buffer, out T payload, out int consumed);
    static abstract int Write(Span<byte> destination, in T packet);

    int WireLength { get; }
}