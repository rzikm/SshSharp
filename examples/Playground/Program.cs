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

// var endpoint = new DnsEndPoint("radekzikmund-desktop", 22);
var endpoint = new DnsEndPoint("localhost", 22);

var connection = SshConnection.Connect(endpoint);