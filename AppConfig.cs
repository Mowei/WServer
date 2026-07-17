namespace WebServer
{
    public class AppConfig
    {
        public required string ServerUrl { get; set; }
        public required string PathPrefix { get; set; }
        public required string ListenIp { get; set; }
        public required int ListenPort { get; set; }
        public required bool VerifyTls { get; set; }
    }
}
