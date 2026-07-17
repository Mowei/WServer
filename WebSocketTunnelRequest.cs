namespace WebServer
{
    public class WebSocketTunnelRequest
    {
        public WebSocketTunnelRequest(string targetHost, int targetPort)
        {
            TargetHost = targetHost;
            TargetPort = targetPort;
        }

        public string TargetHost { get; }
        public int TargetPort { get; }
    }
}
