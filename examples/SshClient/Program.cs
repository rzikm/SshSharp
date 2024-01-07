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

var endpoint = new DnsEndPoint("radekzikmund-desktop", 22);
// var endpoint = new DnsEndPoint("localhost", 22);

using var connection = await SshConnection.ConnectAsync(endpoint);

var channel = await connection.ExecuteShellAsync();

var consoleOut = Console.OpenStandardOutput();

_ = Task.Run(async () =>
{
    channel.GetOutputStream();
    var buffer = new byte[1024];
    while (true)
    {
        var read = await channel.GetOutputStream().ReadAsync(buffer).ConfigureAwait(false);
        if (read == 0)
        {
            break;
        }
        await consoleOut.WriteAsync(buffer.AsMemory(0, read)).ConfigureAwait(false);
        await consoleOut.FlushAsync().ConfigureAwait(false);
    }
});

var writer = new StreamWriter(channel.GetInputStream());
writer.AutoFlush = true;

while (true)
{
    var line = Console.ReadLine();
    if (line == "exit")
    {
        break;
    }
    await writer.WriteLineAsync(line);
    // await writer.WriteLineAsync("ls");
}
