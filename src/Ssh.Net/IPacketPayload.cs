namespace Ssh.Net;

internal interface IPacketPayload<T> : IPayload<T>
{
    static abstract MessageId MessageId { get; }
}

internal interface IUserauthMethod<T> : IPayload<T>
{
    static abstract string Name { get; }
}

internal interface IPayload<T>
{
    static abstract bool TryRead(ReadOnlySpan<byte> buffer, out T payload, out int consumed);
    static abstract int Write(Span<byte> destination, in T packet);

    int WireLength { get; }
}