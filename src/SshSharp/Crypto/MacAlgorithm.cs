using System.Buffers.Binary;
using System.Security.Cryptography;
using SshSharp.Utils;

namespace SshSharp.Crypto;

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
            "hmac-sha1" => new HmacShaAlgorithm<HmacSha1Adatper>(initialSequenceNumber, keyGenerator),
            "hmac-sha2-256" => new HmacShaAlgorithm<HmacSha256Adatper>(initialSequenceNumber, keyGenerator),
            "hmac-sha2-512" => new HmacShaAlgorithm<HmacSha512Adatper>(initialSequenceNumber, keyGenerator),
            _ => throw new Exception($"Unsupported mac algorithm: {name}")
        };
    }
}

internal interface IHmacAdapter
{
    public static abstract int MacSize { get; }
    public static abstract int KeySize { get; }
    public static abstract void HashData(byte[] key, ReadOnlySpan<byte> buffer, Span<byte> result);
}

internal class HmacSha1Adatper : IHmacAdapter
{
    public static int MacSize => SHA1.HashSizeInBytes;
    public static int KeySize => SHA1.HashSizeInBytes;
    public static void HashData(byte[] key, ReadOnlySpan<byte> buffer, Span<byte> result) => HMACSHA1.HashData(key, buffer, result);
}

internal class HmacSha256Adatper : IHmacAdapter
{
    public static int MacSize => SHA256.HashSizeInBytes;
    public static int KeySize => SHA256.HashSizeInBytes;
    public static void HashData(byte[] key, ReadOnlySpan<byte> buffer, Span<byte> result) => HMACSHA256.HashData(key, buffer, result);
}

internal class HmacSha512Adatper : IHmacAdapter
{
    public static int MacSize => SHA512.HashSizeInBytes;
    public static int KeySize => SHA512.HashSizeInBytes;
    public static void HashData(byte[] key, ReadOnlySpan<byte> buffer, Span<byte> result) => HMACSHA512.HashData(key, buffer, result);
}

internal class HmacShaAlgorithm<THmac> : MacAlgorithm where THmac : IHmacAdapter
{
    private readonly byte[] _key;

    public HmacShaAlgorithm(uint sequence, Func<int, byte[]> keyGenerator) : base(sequence)
    {
        _key = keyGenerator(THmac.KeySize);
    }

    public override string Name => "hmac-sha1";

    public override int MacSize => THmac.MacSize;
    public override int KeySize => THmac.MacSize;

    protected override void SignInternal(Span<byte> buffer, Span<byte> signature)
    {
        // prepend the sequence number
        Span<byte> tmpBuff = stackalloc byte[buffer.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(tmpBuff, SequenceNumber);
        buffer.CopyTo(tmpBuff.Slice(4));
        THmac.HashData(_key, tmpBuff, signature);
    }

    protected override bool VerifyInternal(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> signature)
    {
        Span<byte> tmpBuff = stackalloc byte[buffer.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(tmpBuff, SequenceNumber);
        buffer.CopyTo(tmpBuff.Slice(4));

        Span<byte> result = stackalloc byte[signature.Length];
        THmac.HashData(_key, tmpBuff, result);

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
