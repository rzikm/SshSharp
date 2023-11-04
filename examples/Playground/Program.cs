using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

using Ssh.Net;
using Ssh.Net.Packets;
using Ssh.Net.Transport;
using Ssh.Net.Utils;

// var endpoint = new DnsEndPoint("radekzikmund-desktop", 22);
var endpoint = new DnsEndPoint("localhost", 22);

var connection = SshConnection.Connect(endpoint);