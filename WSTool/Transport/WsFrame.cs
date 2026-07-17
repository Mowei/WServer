namespace WSTool.Transport;

public readonly struct WsFrame
{
    public WsFrame(byte opcode, byte[] payload)
    {
        Opcode = opcode;
        Payload = payload;
    }

    public byte Opcode { get; }
    public byte[] Payload { get; }
}
