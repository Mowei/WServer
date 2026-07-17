using System.Text;

namespace WSTool.Utils;

public static class HttpStreamUtil
{
    public static string GetFirstLine(byte[] data)
    {
        var s = Encoding.ASCII.GetString(data);
        var i = s.IndexOf("\r\n", StringComparison.Ordinal);
        return i >= 0 ? s[..i] : s;
    }

    public static async Task<byte[]> ReadHttpHeadAsync(Stream stream, CancellationToken ct = default)
    {
        var buffer = new byte[4096];
        using var ms = new MemoryStream();
        while (ms.Length < 65536)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
            if (read <= 0)
            {
                break;
            }

            ms.Write(buffer, 0, read);
            if (EndsWithHttpHead(ms.GetBuffer(), (int)ms.Length))
            {
                break;
            }
        }

        return ms.ToArray();
    }

    public static Task WriteAsciiAsync(Stream stream, string text, CancellationToken ct = default)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        return stream.WriteAsync(bytes.AsMemory(0, bytes.Length), ct).AsTask();
    }

    private static bool EndsWithHttpHead(byte[] data, int len)
    {
        if (len < 4)
        {
            return false;
        }

        for (var i = 3; i < len; i++)
        {
            if (data[i - 3] == '\r' && data[i - 2] == '\n' && data[i - 1] == '\r' && data[i] == '\n')
            {
                return true;
            }
        }

        return false;
    }
}
