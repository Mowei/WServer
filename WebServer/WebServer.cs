using System.Net;
using System.Net.Sockets;
using System.Text;
using WSTool.Configuration;
using WSTool.Contracts;
using WSTool.Transport;

internal static partial class Program
{
    private const string DefaultServerUrl = "";
    private const string DefaultPathPrefix = "v1";
    private const string DefaultListenIp = "127.0.0.1";
    private const int DefaultListenPort = 3456;

    private static async Task Main(string[] args)
    {
        var cfg = ParseArgs(args);
        PrintEffectiveConfig(cfg);

        var listener = new TcpListener(IPAddress.Parse(cfg.ListenIp), cfg.ListenPort);
        listener.Start(128);
        Console.WriteLine($"HTTP proxy listening on {cfg.ListenIp}:{cfg.ListenPort} -> {cfg.ServerUrl}");

        while (true)
        {
            var client = await listener.AcceptTcpClientAsync();
            _ = Task.Run(() => HandleClientAsync(client, cfg));
        }
    }

    private static async Task HandleClientAsync(TcpClient client, AppConfig cfg)
    {
        WebSocketToolStream? ws = null;
        await using var wsClient = new WebSocketToolAdapter(cfg);
        try
        {
            var clientStream = client.GetStream();
            var head = await ReadHttpHeadAsync(clientStream);
            if (head.Length == 0)
            {
                return;
            }

            var firstLine = GetFirstLine(head);
            var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                await WriteAsciiAsync(clientStream, "HTTP/1.1 405 Method Not Allowed\r\n\r\n");
                return;
            }

            var (host, port) = ParseConnectAuthority(parts[1]);

            Console.WriteLine($"[connect] {host}:{port}");
            ws = await wsClient.OpenAsync(new WebSocketToolRequest(host, port));

            await WriteAsciiAsync(clientStream, "HTTP/1.1 200 OK\r\n\r\n");
            await RelayAsync(clientStream, ws);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[tunnel] error: {ex.Message}");
        }
        finally
        {
            if (ws is not null)
            {
                await ws.DisposeAsync();
            }

            client.Close();
        }
    }

    private static async Task RelayAsync(NetworkStream local, WebSocketToolStream ws)
    {
        using var cts = new CancellationTokenSource();

        var localToWs = Task.Run(async () =>
        {
            var buf = new byte[64 * 1024];
            while (!cts.IsCancellationRequested)
            {
                var read = await local.ReadAsync(buf, 0, buf.Length, cts.Token);
                if (read <= 0)
                {
                    break;
                }

                await ws.SendFrameAsync(0x2, new ReadOnlyMemory<byte>(buf, 0, read), cts.Token);
            }
        }, cts.Token);

        var wsToLocal = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                var frame = await ws.ReadFrameAsync(cts.Token);
                if (frame is null)
                {
                    break;
                }

                switch (frame.Value.Opcode)
                {
                    case 0x2: // binary
                        await local.WriteAsync(frame.Value.Payload, cts.Token);
                        await local.FlushAsync(cts.Token);
                        break;
                    case 0x1: // text
                        await local.WriteAsync(frame.Value.Payload, cts.Token);
                        await local.FlushAsync(cts.Token);
                        break;
                    case 0x9: // ping
                        await ws.SendFrameAsync(0xA, frame.Value.Payload, cts.Token); // pong
                        break;
                    case 0x8: // close
                        return;
                }
            }
        }, cts.Token);

        await Task.WhenAny(localToWs, wsToLocal);
        cts.Cancel();

        try { await localToWs; } catch { }
        try { await wsToLocal; } catch { }

        try
        {
            await ws.SendFrameAsync(0x8, ReadOnlyMemory<byte>.Empty, CancellationToken.None);
        }
        catch
        {
            // Ignore close errors.
        }
    }

    private static AppConfig ParseArgs(string[] args)
    {
        var cfg = new AppConfig
        {
            ServerUrl = GetEnv("WST_SERVER", DefaultServerUrl),
            PathPrefix = GetEnv("WST_PATH_PREFIX", DefaultPathPrefix),
            ListenIp = GetEnv("WST_LISTEN_IP", DefaultListenIp),
            ListenPort = GetEnvInt("WST_LISTEN_PORT", DefaultListenPort),
            VerifyTls = GetEnvBool("WST_VERIFY_TLS", false)
        };

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--server":
                case "-s":
                    cfg.ServerUrl = NextValue(args, ref i, "--server");
                    break;
                case "--path-prefix":
                case "-P":
                    cfg.PathPrefix = NextValue(args, ref i, "--path-prefix");
                    break;
                case "--listen-ip":
                case "-l":
                    cfg.ListenIp = NextValue(args, ref i, "--listen-ip");
                    break;
                case "--listen-port":
                case "-p":
                    cfg.ListenPort = int.Parse(NextValue(args, ref i, "--listen-port"));
                    break;
                case "--verify-tls":
                case "-k":
                    cfg.VerifyTls = true;
                    break;
                case "-h":
                case "--help":
                    PrintHelpAndExit();
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        var uri = new Uri(cfg.ServerUrl);
        if (!uri.Scheme.Equals("ws", StringComparison.OrdinalIgnoreCase) &&
            !uri.Scheme.Equals("wss", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("--server must use ws:// or wss://");
        }

        return cfg;
    }

    private static string NextValue(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
        {
            throw new ArgumentException($"Missing value for {flag}");
        }

        i++;
        return args[i];
    }

    private static void PrintHelpAndExit()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  proxy [-s|--server URL] [-P|--path-prefix PREFIX] [-l|--listen-ip IP] [-p|--listen-port PORT] [-k|--verify-tls]");
        Console.WriteLine("Environment variables:");
        Console.WriteLine("  WST_SERVER, WST_PATH_PREFIX, WST_LISTEN_IP, WST_LISTEN_PORT, WST_VERIFY_TLS");
        Environment.Exit(0);
    }

    private static string GetEnv(string name, string fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static int GetEnvInt(string name, int fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return int.TryParse(value, out var parsed) ? parsed : fallback;
    }

    private static bool GetEnvBool(string name, bool fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "1" or "true" or "yes" or "on" => true,
            "0" or "false" or "no" or "off" => false,
            _ => fallback
        };
    }

    private static void PrintEffectiveConfig(AppConfig cfg)
    {
        Console.WriteLine("Effective config:");
        Console.WriteLine($"  server: {cfg.ServerUrl}");
        Console.WriteLine($"  path_prefix: {cfg.PathPrefix}");
        Console.WriteLine($"  listen_ip: {cfg.ListenIp}");
        Console.WriteLine($"  listen_port: {cfg.ListenPort}");
        Console.WriteLine($"  verify_tls: {cfg.VerifyTls}");
    }

    private static (string Host, int Port) ParseConnectAuthority(string authority)
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



    private static string GetFirstLine(byte[] data)
    {
        var s = Encoding.ASCII.GetString(data);
        var i = s.IndexOf("\r\n", StringComparison.Ordinal);
        return i >= 0 ? s[..i] : s;
    }

    private static async Task<byte[]> ReadHttpHeadAsync(Stream stream)
    {
        var buffer = new byte[4096];
        using var ms = new MemoryStream();
        while (ms.Length < 65536)
        {
            var read = await stream.ReadAsync(buffer, 0, buffer.Length);
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

    private static Task WriteAsciiAsync(Stream stream, string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        return stream.WriteAsync(bytes, 0, bytes.Length);
    }
}
