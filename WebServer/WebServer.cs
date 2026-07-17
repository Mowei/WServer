using System.Net;
using System.Net.Sockets;
using WebServer.Configuration;
using WebServer.Utils;
using WSTool.Contracts;
using WSTool.Transport;
using WSTool.Utils;

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
        /*
        var wsClient = new WebSocketToolAdapter(cfg);
        
        var wsHttpClient = wsClient.CreateHttpClient();
        var wsResponse = await wsHttpClient.GetAsync("https://www.google.com");
        Console.WriteLine($"[test] status: {wsResponse.StatusCode} Body {await wsResponse.Content.ReadAsStringAsync()}");
        */
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
            var head = await HttpStreamUtil.ReadHttpHeadAsync(clientStream);
            if (head.Length == 0)
            {
                return;
            }

            var firstLine = HttpStreamUtil.GetFirstLine(head);
            var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || !parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                await HttpStreamUtil.WriteAsciiAsync(clientStream, "HTTP/1.1 405 Method Not Allowed\r\n\r\n");
                return;
            }

            var (host, port) = ConnectAuthorityUtil.Parse(parts[1]);

            Console.WriteLine($"[connect] {host}:{port}");
            ws = await wsClient.OpenAsync(new WebSocketToolRequest(host, port));

            await HttpStreamUtil.WriteAsciiAsync(clientStream, "HTTP/1.1 200 OK\r\n\r\n");
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
            ServerUrl = EnvironmentUtil.GetEnv("WST_SERVER", DefaultServerUrl),
            PathPrefix = EnvironmentUtil.GetEnv("WST_PATH_PREFIX", DefaultPathPrefix),
            ListenIp = EnvironmentUtil.GetEnv("WST_LISTEN_IP", DefaultListenIp),
            ListenPort = EnvironmentUtil.GetEnvInt("WST_LISTEN_PORT", DefaultListenPort),
            VerifyTls = EnvironmentUtil.GetEnvBool("WST_VERIFY_TLS", false)
        };

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--server":
                case "-s":
                    cfg.ServerUrl = CommandLineUtil.NextValue(args, ref i, "--server");
                    break;
                case "--path-prefix":
                case "-P":
                    cfg.PathPrefix = CommandLineUtil.NextValue(args, ref i, "--path-prefix");
                    break;
                case "--listen-ip":
                case "-l":
                    cfg.ListenIp = CommandLineUtil.NextValue(args, ref i, "--listen-ip");
                    break;
                case "--listen-port":
                case "-p":
                    cfg.ListenPort = int.Parse(CommandLineUtil.NextValue(args, ref i, "--listen-port"));
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

    private static void PrintHelpAndExit()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  proxy [-s|--server URL] [-P|--path-prefix PREFIX] [-l|--listen-ip IP] [-p|--listen-port PORT] [-k|--verify-tls]");
        Console.WriteLine("Environment variables:");
        Console.WriteLine("  WST_SERVER, WST_PATH_PREFIX, WST_LISTEN_IP, WST_LISTEN_PORT, WST_VERIFY_TLS");
        Environment.Exit(0);
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

}
