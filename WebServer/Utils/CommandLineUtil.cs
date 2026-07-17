namespace WebServer.Utils;

public static class CommandLineUtil
{
    public static string NextValue(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
        {
            throw new ArgumentException($"Missing value for {flag}");
        }

        i++;
        return args[i];
    }
}
