using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Utils;

namespace SshSharp.Unit.Tests;

public class KeyDerivationTests
{
    [Fact]
    public void DerivesCorrectKeys()
    {
        const string sharedSecret = "05-6A-A7-A8-13-55-1C-39-4D-B0-3C-9E-C6-3C-F0-1C-A3-DA-D5-F6-39-17-10-BA-C3-96-92-27-52-C3-3F-0B";

        const string exchangeHash = "09-07-86-31-5F-88-ED-24-F3-AB-2D-2F-36-2C-1F-19-95-DD-02-E0-A6-47-A0-BC-28-07-DC-55-81-AD-2B-39";

        const string clientIv = "53-EA-93-11-62-A3-D7-33-7C-F6-6E-02-38-86-92-25-85-33-89-59-02-B9-3E-F3-0C-FD-78-FF-8C-5E-49-0C";

        const string clientEncryptionKey = "3D-A7-4E-7B-2E-23-69-39-C6-9B-2B-3D-4C-FA-43-13-0B-09-DA-05-75-2E-4A-6C-0B-23-35-83-7B-4A-E6-A6";

        const string clientHashKey = "E7-02-55-87-F2-D5-58-76-CE-7B-DF-E5-0D-3D-A0-4B-BD-24-29-75-B6-43-27-07-D7-02-10-6C-3D-85-49-C0";

        KeyExchangeCurve25519Sha256 keyExchange = new();

        byte[] HashHelper(char c)
        {
            return KeyGenerationHelpers.DeriveSessionKey(
                HexToBytes(sharedSecret),
                HexToBytes(exchangeHash),
                c,
                HexToBytes(exchangeHash),
                keyExchange,
                32
            );
        }

        Assert.Equal(clientIv, BytesToHex(HashHelper('A')));
        Assert.Equal(clientEncryptionKey, BytesToHex(HashHelper('C')));
        Assert.Equal(clientHashKey, BytesToHex(HashHelper('E')));
    }

    [Fact]
    public void DerivesShorterOrLongerKeys()
    {
        const string sharedSecret = "05-6A-A7-A8-13-55-1C-39-4D-B0-3C-9E-C6-3C-F0-1C-A3-DA-D5-F6-39-17-10-BA-C3-96-92-27-52-C3-3F-0B";

        const string exchangeHash = "09-07-86-31-5F-88-ED-24-F3-AB-2D-2F-36-2C-1F-19-95-DD-02-E0-A6-47-A0-BC-28-07-DC-55-81-AD-2B-39";

        const string clientIv = "53-EA-93-11-62-A3-D7-33-7C-F6-6E-02-38-86-92-25-85-33-89-59-02-B9-3E-F3-0C-FD-78-FF-8C-5E-49-0C";

        KeyExchangeCurve25519Sha256 keyExchange = new();

        byte[] HashHelper(int len)
        {
            return KeyGenerationHelpers.DeriveSessionKey(
                HexToBytes(sharedSecret),
                HexToBytes(exchangeHash),
                'A',
                HexToBytes(exchangeHash),
                keyExchange,
                len
            );
        }

        // Assert.Equal(clientIv, BytesToHex(HashHelper(32)));
        // Assert.Equal(clientIv.Substring(0, clientIv.Length - 3), BytesToHex(HashHelper(31)));
        Assert.StartsWith(clientIv, BytesToHex(HashHelper(33)));
    }

    public byte[] HexToBytes(string hex) => hex.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();
    public string BytesToHex(ReadOnlySpan<byte> bytes) => BitConverter.ToString(bytes.ToArray());
}

