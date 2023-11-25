using System;
using System.Security.Cryptography;
using SshSharp.Utils;

namespace SshSharp.Crypto;

internal abstract class EncryptionAlgorithm
{
    public abstract string Name { get; }

    public abstract int BlockSize { get; }

    public abstract void Encrypt(Span<byte> buffer);
    public abstract void Decrypt(Span<byte> buffer);

    public static EncryptionAlgorithm Create(string name, Func<int, byte[]> ivGenerator, Func<int, byte[]> keyGenerator)
    {
        return name switch
        {
            "none" => NullEncryptionAlgorithm.Instance,
            "aes128-ctr" => new AesCtrEncryptionAlgorithm(name, 128, ivGenerator(16), keyGenerator(128 / 8)),
            "aes192-ctr" => new AesCtrEncryptionAlgorithm(name, 192, ivGenerator(16), keyGenerator(192 / 8)),
            "aes256-ctr" => new AesCtrEncryptionAlgorithm(name, 256, ivGenerator(16), keyGenerator(256 / 8)),
            _ => throw new Exception($"Unsupported encryption algorithm: {name}")
        };
    }
}

internal class AesCtrEncryptionAlgorithm : EncryptionAlgorithm
{
    Aes _aes;

    byte[] counter;

    public AesCtrEncryptionAlgorithm(string name, int v, byte[] iv, byte[] key)
    {
        Name = name;

        // System.Console.WriteLine($"IV: {BitConverter.ToString(iv)}");
        // System.Console.WriteLine($"Key: {BitConverter.ToString(key)}");

        _aes = Aes.Create();
        _aes.KeySize = v;

        counter = iv[0..BlockSize];

        _aes.IV = new byte[BlockSize];
        _aes.Key = key[0..(_aes.KeySize / 8)];
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
    }

    public override string Name { get; }

    public override int BlockSize => _aes.BlockSize / 8;

    private void IncrementCounter()
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }

    public override void Encrypt(Span<byte> buffer)
    {
        if (buffer.Length % BlockSize != 0)
        {
            throw new Exception("Buffer size is not a multiple of block size");
        }

        Span<byte> mask = stackalloc byte[BlockSize];

        for (int i = 0; i < buffer.Length; i += BlockSize)
        {
            _aes.EncryptEcb(counter, mask, PaddingMode.None);
            IncrementCounter();

            for (int j = 0; j < BlockSize; j++)
            {
                buffer[i + j] ^= mask[j];
            }
        }
    }

    public override void Decrypt(Span<byte> buffer)
    {
        Encrypt(buffer);
    }
}

internal class NullEncryptionAlgorithm : EncryptionAlgorithm
{
    public static readonly NullEncryptionAlgorithm Instance = new NullEncryptionAlgorithm();

    private NullEncryptionAlgorithm()
    {
    }

    public override string Name => "none";

    public override int BlockSize => 8;

    public override void Decrypt(Span<byte> buffer)
    {
    }

    public override void Encrypt(Span<byte> buffer)
    {
    }
}