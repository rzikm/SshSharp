using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

using Ssh.Net;
using Ssh.Net.Utils;

var endpoint = new DnsEndPoint("radekzikmund-desktop", 22);
// var endpoint = new DnsEndPoint("localhost", 22);

var sock = new Socket(SocketType.Stream, ProtocolType.Tcp);
sock.Connect(endpoint);

var stream = new NetworkStream(sock, ownsSocket: true);

var buffer = new byte[64 * 1024];

int bytes = 0;
int index = -1;

do
{
    bytes += stream.Read(buffer.AsSpan(bytes));
    index = buffer.AsSpan(0, bytes).IndexOf("\r\n"u8);
} while (index == -1);

var version = Encoding.UTF8.GetString(buffer.AsSpan(0, index));
System.Console.WriteLine($"Server version: {version}");

stream.Write("SSH-2.0-SSH_NET_0.0.0\r\n"u8);

SshPacket packet;
ReceiveSshPacket(out packet);

var payload = packet.Payload;

if ((MessageId)payload[0] != MessageId.SSH_MSG_KEXINIT)
{
    throw new Exception("Expected SSH_MSG_KEXINIT.");
}

if (!KeyExchangeInitPacket.TryRead(packet.Payload, out var serverKexPacket, out _))
{
    throw new Exception("Failed to read key exchange algorithms.");
}

Console.WriteLine((MessageId)payload[0]);
Console.WriteLine($"KeyExchangeAlgorithms: {string.Join(",", serverKexPacket.KeyExchangeAlgorithms)}");
Console.WriteLine($"ServerHostKeyAlgorithms: {string.Join(",", serverKexPacket.ServerHostKeyAlgorithms)}");
Console.WriteLine($"EncryptionAlgorithmsClientToServer: {string.Join(",", serverKexPacket.EncryptionAlgorithmsClientToServer)}");
Console.WriteLine($"EncryptionAlgorithmsServerToClient: {string.Join(",", serverKexPacket.EncryptionAlgorithmsServerToClient)}");
Console.WriteLine($"MacAlgorithmsClientToServer: {string.Join(",", serverKexPacket.MacAlgorithmsClientToServer)}");
Console.WriteLine($"MacAlgorithmsServerToClient: {string.Join(",", serverKexPacket.MacAlgorithmsServerToClient)}");
Console.WriteLine($"CompressionAlgorithmsClientToServer: {string.Join(",", serverKexPacket.CompressionAlgorithmsClientToServer)}");
Console.WriteLine($"CompressionAlgorithmsServerToClient: {string.Join(",", serverKexPacket.CompressionAlgorithmsServerToClient)}");
Console.WriteLine($"LanguagesClientToServer: {string.Join(",", serverKexPacket.LanguagesClientToServer)}");
Console.WriteLine($"LanguagesServerToClient: {string.Join(",", serverKexPacket.LanguagesServerToClient)}");
Console.WriteLine($"FirstKexPacketFollows: {serverKexPacket.FirstKexPacketFollows}");
Console.WriteLine($"Reserved: {serverKexPacket.Reserved}");
System.Console.WriteLine();

var clientKexPacket = serverKexPacket;
// clientKexPacket.Cookie = (UInt128)Random.Shared.Next();
// clientKexPacket.KeyExchangeAlgorithms = "curve25519-sha256";
// clientKexPacket.ServerHostKeyAlgorithms = "rsa-sha2-512";

SendPacket(clientKexPacket);

ReceiveSshPacket(out packet);
Console.WriteLine((MessageId)payload[0]);

void ReceiveSshPacket(out SshPacket packet)
{
    int bytes = 0;
    int consumed = 0;
    do
    {
        bytes += stream.Read(buffer.AsSpan(bytes));
    } while (!SshPacket.TryRead(buffer.AsSpan(0, bytes), 0, out packet, out consumed));

    System.Console.WriteLine($"Read {consumed} Bytes");

    buffer.AsSpan(consumed, bytes - consumed).CopyTo(buffer);
}

void SendPacket<T>(in T packet) where T : IPacketPayload<T>
{
    int written = PacketHelpers.WritePayload(buffer, packet);
    stream.Write(buffer.AsSpan(0, written));
}