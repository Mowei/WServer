namespace WSTool.Contracts;

public sealed class WebSocketToolRequest
{
    public WebSocketToolRequest(string targetHost, int targetPort)
    {
        TargetHost = targetHost;
        TargetPort = targetPort;
    }

    public string TargetHost { get; }
    public int TargetPort { get; }
}
