using WSTool.Configuration;

namespace WebServer.Configuration;

public sealed class AppConfig : AdapterConfig
{
    public required string ListenIp { get; set; }
    public required int ListenPort { get; set; }
}
