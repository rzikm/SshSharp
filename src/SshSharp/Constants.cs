namespace SshSharp;

internal static class Constants
{
    internal static byte[] VersionBytes = "SSH-2.0-SSH_NET_0.0.1"u8.ToArray();
    internal static byte[] VersionBytesCrLf = "SSH-2.0-SSH_NET_0.0.1\r\n"u8.ToArray();
}