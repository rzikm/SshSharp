using SshSharp;
using SshSharp.Crypto;
using SshSharp.Packets;
using SshSharp.Transport;
using SshSharp.Utils;

using System;
using System.Diagnostics;
using System.Net;
using System.Numerics;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

using System.Text.RegularExpressions;

using Renci.SshNet;
// var endpoint = new DnsEndPoint("radekzikmund-desktop", 22);
var endpoint = new DnsEndPoint("localhost", 22);

var connection = SshConnection.Connect(endpoint);

// var connectionInfo = new ConnectionInfo(endpoint.Host, "EUROPE\\radekzikmund", new PrivateKeyAuthenticationMethod("EUROPE\\radekzikmund", new PrivateKeyFile("C:/Users/radekzikmund/.ssh/id_rsa")));

// using (var client = new SshClient(connectionInfo))
// {
//     client.HostKeyReceived += (sender, e) =>
//         {
//             e.CanTrust = true;
//         };
//     client.Connect();
// }

// static string BytesToHex(ReadOnlySpan<byte> bytes) => BitConverter.ToString(bytes.ToArray());
// static byte[] HexToBytes(string hex) => hex.Split('-').Select(x => Convert.ToByte(x, 16)).ToArray();