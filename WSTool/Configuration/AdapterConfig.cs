namespace WSTool.Configuration;

public class AdapterConfig
{
    public required string ServerUrl { get; set; }
    public required string PathPrefix { get; set; }
    public required bool VerifyTls { get; set; }
}
