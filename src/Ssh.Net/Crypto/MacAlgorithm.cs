using System.Buffers.Binary;
using System.Security.Cryptography;
using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal abstract class MacAlgorithm
{
    public abstract string Name { get; }

    public abstract int MacSize { get; }

    public abstract int KeySize { get; }

    public uint SequenceNumber { get; private set; }

    public MacAlgorithm(uint initialSequenceNumber)
    {
        SequenceNumber = initialSequenceNumber;
    }

    public void Sign(Span<byte> buffer, Span<byte> signature)
    {
        SignInternal(buffer, signature);
        SequenceNumber++;
    }

    public bool Verify(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> signature)
    {
        var result = VerifyInternal(buffer, signature);
        SequenceNumber++;
        return result;
    }

    protected abstract void SignInternal(Span<byte> buffer, Span<byte> signature);

    protected abstract bool VerifyInternal(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> signature);

    public static MacAlgorithm Create(string name, uint initialSequenceNumber, Func<int, byte[]> keyGenerator)
    {
        return name switch
        {
            "none" => NullMacAlgorithm.Instance,
            "hmac-sha1" => new HmacShaMacAlgorithm(initialSequenceNumber, keyGenerator(20)),
            // "hmac-sha2-256" => new HmacSha256MacAlgorithm(key),
            // "hmac-sha2-512" => new HmacSha512MacAlgorithm(key),
            _ => throw new Exception($"Unsupported mac algorithm: {name}")
        };
    }
}

internal class HmacShaMacAlgorithm : MacAlgorithm
{
    private readonly byte[] key;

    public HmacShaMacAlgorithm(uint sequence, byte[] key) : base(sequence)
    {
        // System.Console.WriteLine($"Mac key: {BitConverter.ToString(key)}");
        this.key = key;
    }

    public override string Name => "hmac-sha1";

    public override int MacSize => SHA1.HashSizeInBytes;
    public override int KeySize => SHA1.HashSizeInBytes;

    protected override void SignInternal(Span<byte> buffer, Span<byte> signature)
    {
        // prepend the sequence number
        Span<byte> tmpBuff = stackalloc byte[buffer.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(tmpBuff, SequenceNumber);
        buffer.CopyTo(tmpBuff.Slice(4));
        HMACSHA1.HashData(key, tmpBuff, signature);
    }

    protected override bool VerifyInternal(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> signature)
    {
        Span<byte> tmpBuff = stackalloc byte[buffer.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(tmpBuff, SequenceNumber);
        buffer.CopyTo(tmpBuff.Slice(4));

        Span<byte> result = stackalloc byte[signature.Length];
        HMACSHA1.HashData(key, tmpBuff, result);

        return signature.SequenceEqual(result);
    }
}

internal class NullMacAlgorithm : MacAlgorithm
{
    public static readonly NullMacAlgorithm Instance = new NullMacAlgorithm();

    public NullMacAlgorithm(uint sequence = 0) : base(sequence)
    {
    }

    public override string Name => "none";

    public override int MacSize => 0;

    public override int KeySize => 0;

    protected override void SignInternal(Span<byte> buffer, Span<byte> signature)
    {
    }

    protected override bool VerifyInternal(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> signature)
    {
        return true;
    }
}
