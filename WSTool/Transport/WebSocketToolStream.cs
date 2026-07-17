using System.Buffers.Binary;
using System.Net.Sockets;

namespace WSTool.Transport;

public sealed class WebSocketToolStream : Stream
{
    private readonly TcpClient _tcp;
    private readonly Stream _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    private byte[] _readBuffer = Array.Empty<byte>();
    private int _readOffset;
    private bool _disposed;

    public WebSocketToolStream(TcpClient tcp, Stream stream)
    {
        _tcp = tcp;
        _stream = stream;
    }

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
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

    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
        {
            return 0;
        }

        while (true)
        {
            var available = _readBuffer.Length - _readOffset;
            if (available > 0)
            {
                var copyLen = Math.Min(buffer.Length, available);
                _readBuffer.AsSpan(_readOffset, copyLen).CopyTo(buffer.Span);
                _readOffset += copyLen;

                if (_readOffset >= _readBuffer.Length)
                {
                    _readBuffer = Array.Empty<byte>();
                    _readOffset = 0;
                }

                return copyLen;
            }

            var frame = await ReadFrameAsync(cancellationToken);
            if (frame is null)
            {
                return 0;
            }

            switch (frame.Value.Opcode)
            {
                case 0x2:
                case 0x1:
                    _readBuffer = frame.Value.Payload;
                    _readOffset = 0;
                    break;
                case 0x9:
                    await SendFrameAsync(0xA, frame.Value.Payload, cancellationToken);
                    break;
                case 0x8:
                    return 0;
            }
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await SendFrameAsync(0x2, buffer, cancellationToken);
    }

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        try { _stream.Close(); } catch { }
        try { _tcp.Close(); } catch { }
        _sendLock.Dispose();
        await Task.CompletedTask;

        _disposed = true;

        GC.SuppressFinalize(this);
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        base.Dispose(disposing);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
