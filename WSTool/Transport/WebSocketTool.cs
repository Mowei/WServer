using System.Buffers.Binary;
using System.Net.Sockets;

namespace WSTool.Transport;

public sealed class WebSocketTool : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private readonly Stream _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    public WebSocketTool(TcpClient tcp, Stream stream)
    {
        _tcp = tcp;
        _stream = stream;
    }

    public async Task SendFrameAsync(byte opcode, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        await _sendLock.WaitAsync(ct);
        try
        {
            var len = payload.Length;
            var header = new List<byte>(14)
            {
                (byte)(0x80 | (opcode & 0x0F))
            };

            if (len <= 125)
            {
                header.Add((byte)(0x80 | len));
            }
            else if (len <= ushort.MaxValue)
            {
                header.Add(0x80 | 126);
                header.Add((byte)((len >> 8) & 0xFF));
                header.Add((byte)(len & 0xFF));
            }
            else
            {
                header.Add(0x80 | 127);
                Span<byte> tmp = stackalloc byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(tmp, (ulong)len);
                header.AddRange(tmp.ToArray());
            }

            header.Add(0x00);
            header.Add(0x00);
            header.Add(0x00);
            header.Add(0x00);

            await _stream.WriteAsync(header.ToArray(), 0, header.Count, ct);
            if (len > 0)
            {
                await _stream.WriteAsync(payload, ct);
            }

            await _stream.FlushAsync(ct);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async Task<WsFrame?> ReadFrameAsync(CancellationToken ct)
    {
        var hdr = new byte[2];
        if (!await ReadExactAsync(_stream, hdr, 0, 2, ct))
        {
            return null;
        }

        var opcode = (byte)(hdr[0] & 0x0F);
        var masked = (hdr[1] & 0x80) != 0;
        ulong payloadLen = (ulong)(hdr[1] & 0x7F);

        if (payloadLen == 126)
        {
            var ext = new byte[2];
            if (!await ReadExactAsync(_stream, ext, 0, 2, ct))
            {
                return null;
            }

            payloadLen = BinaryPrimitives.ReadUInt16BigEndian(ext);
        }
        else if (payloadLen == 127)
        {
            var ext = new byte[8];
            if (!await ReadExactAsync(_stream, ext, 0, 8, ct))
            {
                return null;
            }

            payloadLen = BinaryPrimitives.ReadUInt64BigEndian(ext);
            if (payloadLen > int.MaxValue)
            {
                throw new IOException("frame too large");
            }
        }

        byte[] mask = Array.Empty<byte>();
        if (masked)
        {
            mask = new byte[4];
            if (!await ReadExactAsync(_stream, mask, 0, 4, ct))
            {
                return null;
            }
        }

        var payload = new byte[(int)payloadLen];
        if (payloadLen > 0 && !await ReadExactAsync(_stream, payload, 0, (int)payloadLen, ct))
        {
            return null;
        }

        if (masked)
        {
            for (var i = 0; i < payload.Length; i++)
            {
                payload[i] ^= mask[i % 4];
            }
        }

        return new WsFrame(opcode, payload);
    }

    public async ValueTask DisposeAsync()
    {
        try { _stream.Close(); } catch { }
        try { _tcp.Close(); } catch { }
        _sendLock.Dispose();
        await Task.CompletedTask;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buf, int off, int len, CancellationToken ct)
    {
        var n = 0;
        while (n < len)
        {
            var r = await stream.ReadAsync(buf, off + n, len - n, ct);
            if (r <= 0)
            {
                return false;
            }

            n += r;
        }

        return true;
    }
}
