using System.Security.Cryptography;
using Ssh.Net.Crypto;

namespace Ssh.Net.Unit.Tests;

public class EncryptionTests
{
    [Fact]
    public void GeneratesMaskCorrectly()
    {
        const string clientIv = "46-7F-BE-E5-0F-EE-8E-62-3A-29-79-81-F8-02-43-5D";
        const string clientKey = "12-8A-5A-6E-2E-AC-E7-69-F7-0C-D1-A9-FB-9D-A4-DB-5F-62-62-A7-16-B5-32-26-55-D8-56-33-B7-6F-7F-1B";

        const string expectedMask = "9F-CD-11-D5-70-05-2A-28-69-2A-B1-7D-7A-8B-C2-E1";

        AesCtrEncryptionAlgorithm aes = new AesCtrEncryptionAlgorithm("aes256-ctr", 256, HexToBytes(clientIv), HexToBytes(clientKey));

        byte[] data = new byte[16];
        aes.Encrypt(data);

        Assert.Equal(expectedMask, BytesToHex(data));
    }

    [Fact]
    public void EncryptsCorrectly()
    {
        const string clientIv = "46-7F-BE-E5-0F-EE-8E-62-3A-29-79-81-F8-02-43-5D";
        const string clientKey = "12-8A-5A-6E-2E-AC-E7-69-F7-0C-D1-A9-FB-9D-A4-DB-5F-62-62-A7-16-B5-32-26-55-D8-56-33-B7-6F-7F-1B";

        const string rawPacketData = "00-00-00-2C-1A-05-00-00-00-0C-73-73-68-2D-75-73-65-72-61-75-74-68-EA-97-5F-2D-CE-C0-DF-F5-23-0A-10-38-7F-9B-14-2E-C9-6F-3E-D9-F7-0B-39-7E-60-F7";

        const string encrypted = "9F-CD-11-F9-6A-00-2A-28-69-26-C2-0E-12-A6-B7-92-AD-4A-63-FA-DE-3A-16-16-1F-45-8B-9B-19-AD-76-8C-5A-16-34-5B-2D-2A-A9-B7-C1-5D-2A-58-77-14-F6-2C";

        AesCtrEncryptionAlgorithm aes = new AesCtrEncryptionAlgorithm("aes256-ctr", 256, HexToBytes(clientIv), HexToBytes(clientKey));

        byte[] data = HexToBytes(rawPacketData);
        aes.Encrypt(data);

        Assert.Equal(encrypted, BytesToHex(data));
    }

    public byte[] HexToBytes(string hex) => hex.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();
    public string BytesToHex(ReadOnlySpan<byte> bytes) => BitConverter.ToString(bytes.ToArray());
}