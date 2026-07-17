namespace WebServer.Utils;

public static class ConnectAuthorityUtil
{
    public static (string Host, int Port) Parse(string authority)
    {
        if (authority.StartsWith("[", StringComparison.Ordinal))
        {
            var end = authority.LastIndexOf("]:", StringComparison.Ordinal);
            if (end <= 0)
            {
                throw new FormatException("invalid IPv6 authority");
            }

            var host = authority.Substring(1, end - 1);
            var port = int.Parse(authority[(end + 2)..]);
            return (host, port);
        }

        var idx = authority.LastIndexOf(':');
        if (idx <= 0)
        {
            throw new FormatException("missing port in CONNECT authority");
        }

        var h = authority[..idx];
        var p = int.Parse(authority[(idx + 1)..]);
        return (h, p);
    }
}
