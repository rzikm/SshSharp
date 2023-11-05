using Ssh.Net.Utils;

namespace Ssh.Net.Crypto;

internal abstract class HostKeyAlgorithm
{
    public abstract string Name { get; }

    public static HostKeyAlgorithm CreateFromWireData(ReadOnlySpan<byte> hostKey)
    {
        SpanReader reader = new SpanReader(hostKey);
        if (!reader.TryReadString(out var hostKeyAlgorithm))
        {
            throw new Exception("Failed to read host key name identifier");
        }

        Console.WriteLine($"Host key algorithm: {hostKeyAlgorithm}");

        switch (hostKeyAlgorithm)
        {
            case "ssh-rsa":
                return HostKeyRsa.CreateFromSerializedParameters(reader);
            default:
                throw new Exception($"Unsupported host key algorithm: {hostKeyAlgorithm}");
        }
    }

    public abstract bool VerifyExchangeHashSignature(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> exchaneSignature);
}