using System.Diagnostics;

public static class Log
{
    [Conditional("DEBUG")]
    public static void Debug(string message)
    {
        Console.WriteLine($"[DBG] {message}");
    }

    [Conditional("DEBUG")]
    public static void Info(string message)
    {
        Console.WriteLine($"[LOG] {message}");
    }
}