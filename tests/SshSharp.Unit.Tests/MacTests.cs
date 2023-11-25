using System.Security.Cryptography;
using SshSharp.Crypto;
using SshSharp.Utils;

namespace SshSharp.Unit.Tests;

public class MacTests
{

    [Fact]
    public void MacSignsCorrectly()
    {
        const string hashKey = "C2-05-E7-B6-E0-50-90-3E-36-60-3D-C5-45-05-71-72-E2-1F-9D-A2";

        const uint sequenceNumber = 3;

        const string RawPacketData = "00-00-00-2C-1A-05-00-00-00-0C-73-73-68-2D-75-73-65-72-61-75-74-68-95-07-56-23-C1-48-D7-5B-13-8F-03-72-46-97-3A-2B-98-52-B6-EF-48-5D-60-E0-03-8F";

        const string expectedMac = "F3-94-C0-EB-83-48-6A-FB-C4-C3-0C-E1-CA-AB-9C-62-F0-50-BA-F7";

        HmacShaMacAlgorithm mac = new HmacShaMacAlgorithm(sequenceNumber, HexToBytes(hashKey));

        Span<byte> macBytes = stackalloc byte[mac.MacSize];

        mac.Sign(HexToBytes(RawPacketData), macBytes);
        Assert.Equal(expectedMac, BytesToHex(macBytes));
    }

    public byte[] HexToBytes(string hex) => hex.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();
    public string BytesToHex(ReadOnlySpan<byte> bytes) => BitConverter.ToString(bytes.ToArray());
}