using System.Buffers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WSTool.Configuration;
using WSTool.Contracts;
using WSTool.Utils;

namespace WSTool.Transport;

public sealed class WebSocketToolAdapter : IAsyncDisposable
{
    private readonly AdapterConfig _cfg;

    public WebSocketToolAdapter(AdapterConfig cfg)
    {
        _cfg = cfg;
    }

    public WebSocketToolAdapter(string serverUrl, string pathPrefix = "v1", bool verifyTls = false)
        : this(CreateConfig(serverUrl, pathPrefix, verifyTls))
    {
    }

    #region HttpClient

    public HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = ConnectOverWebSocketAsync
        };

        return new HttpClient(handler, disposeHandler: true);
    }

    private async ValueTask<Stream> ConnectOverWebSocketAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var endPoint = context.DnsEndPoint ?? throw new IOException("missing destination endpoint");
        return await OpenHttpClientAsync(new WebSocketToolRequest(endPoint.Host, endPoint.Port), ct); ;
    }

    public async Task<WebSocketToolStream> OpenHttpClientAsync(WebSocketToolRequest request, CancellationToken ct = default)
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

        await HttpStreamUtil.WriteAsciiAsync(stream, handshakeRequest, ct);

        var responseHead = await HttpStreamUtil.ReadHttpHeadAsync(stream, ct);
        var statusLine = HttpStreamUtil.GetFirstLine(responseHead);
        if (!statusLine.Contains(" 101 ", StringComparison.Ordinal))
        {
            var preview = Encoding.ASCII.GetString(responseHead);
            throw new IOException($"websocket handshake failed: {statusLine}; response={preview}");
        }

        return new WebSocketToolStream(tcp, stream);
    }

    #endregion

    public async Task<WebSocketToolStream> OpenAsync(WebSocketToolRequest request, CancellationToken ct = default)
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

        await HttpStreamUtil.WriteAsciiAsync(stream, handshakeRequest, ct);

        var responseHead = await HttpStreamUtil.ReadHttpHeadAsync(stream, ct);
        var statusLine = HttpStreamUtil.GetFirstLine(responseHead);
        if (!statusLine.Contains(" 101 ", StringComparison.Ordinal))
        {
            var preview = Encoding.ASCII.GetString(responseHead);
            throw new IOException($"websocket handshake failed: {statusLine}; response={preview}");
        }

        return new WebSocketToolStream(tcp, stream);
    }



    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string MakeJwt(string host, int port)
    {
        var headerBuffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(headerBuffer))
        {
            writer.WriteStartObject();
            writer.WriteString("typ", "JWT");
            writer.WriteString("alg", "HS256");
            writer.WriteEndObject();
        }

        var payloadBuffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(payloadBuffer))
        {
            writer.WriteStartObject();
            writer.WriteString("id", Guid.NewGuid().ToString());
            writer.WritePropertyName("p");
            writer.WriteStartObject();
            writer.WritePropertyName("Tcp");
            writer.WriteStartObject();
            writer.WriteBoolean("proxy_protocol", false);
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WriteString("r", host);
            writer.WriteNumber("rp", port);
            writer.WriteEndObject();
        }

        var header = Base64UrlEncode(headerBuffer.WrittenSpan.ToArray());
        var payload = Base64UrlEncode(payloadBuffer.WrittenSpan.ToArray());

        var signingInput = Encoding.ASCII.GetBytes($"{header}.{payload}");
        using var hmac = new HMACSHA256(Encoding.ASCII.GetBytes("any-secret"));
        var sig = Base64UrlEncode(hmac.ComputeHash(signingInput));
        return $"{header}.{payload}.{sig}";
    }

    public ValueTask DisposeAsync()
    {
        return ValueTask.CompletedTask;
    }


    private static AdapterConfig CreateConfig(string serverUrl, string pathPrefix, bool verifyTls)
    {
        if (string.IsNullOrWhiteSpace(serverUrl))
        {
            throw new ArgumentException("serverUrl is required", nameof(serverUrl));
        }

        return new AdapterConfig
        {
            ServerUrl = serverUrl,
            PathPrefix = pathPrefix,
            VerifyTls = verifyTls,
        };
    }

}
