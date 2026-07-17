using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

internal static partial class Program
{
    private sealed class WebSocketTunnelClient : IAsyncDisposable
    {
        private readonly AppConfig _cfg;

        public WebSocketTunnelClient(AppConfig cfg)
        {
            _cfg = cfg;
        }

        public async Task<WebSocketTunnel> SendAsync(WebSocketTunnelRequest request, CancellationToken ct = default)
        {
            var serverUri = new Uri(_cfg.ServerUrl);
            var tcp = new TcpClient();
            await tcp.ConnectAsync(serverUri.Host, serverUri.Port > 0 ? serverUri.Port : 443, ct);

            Stream stream = tcp.GetStream();
            if (serverUri.Scheme.Equals("wss", StringComparison.OrdinalIgnoreCase))
            {
                var ssl = new SslStream(
                    stream,
                    false,
                    (_, _, _, sslErrors) => !_cfg.VerifyTls || sslErrors == SslPolicyErrors.None
                );
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = serverUri.Host
                }, ct);
                stream = ssl;
            }

            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var jwt = MakeJwt(request.TargetHost, request.TargetPort);
            var handshakeRequest =
                $"GET /{_cfg.PathPrefix}/events HTTP/1.1\r\n" +
                $"Host: {serverUri.Host}\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: upgrade\r\n" +
                $"Sec-WebSocket-Key: {key}\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                $"Sec-WebSocket-Protocol: v1, authorization.bearer.{jwt}\r\n" +
                "\r\n";

            await WriteAsciiAsync(stream, handshakeRequest);

            var responseHead = await ReadHttpHeadAsync(stream);
            var statusLine = GetFirstLine(responseHead);
            if (!statusLine.Contains(" 101 ", StringComparison.Ordinal))
            {
                var preview = Encoding.ASCII.GetString(responseHead);
                throw new IOException($"websocket handshake failed: {statusLine}; response={preview}");
            }

            return new WebSocketTunnel(tcp, stream);
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }
}
