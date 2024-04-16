using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace Controllers;

[ApiController]
[Route("[controller]")]
public class AuthManagerController : ControllerBase
{
    private readonly ILogger<AuthManagerController> _logger;

    public AuthManagerController(ILogger<AuthManagerController> logger)
    {
        _logger = logger;
    }

    [HttpGet("version")]
    public async Task<Dictionary<string, string>> GetVersion()
    {
        var properties = new Dictionary<string, string>();
        var assembly = typeof(Program).Assembly;
        properties.Add("service", "LogisticManager");
        var ver = FileVersionInfo.GetVersionInfo(
        typeof(Program).Assembly.Location).ProductVersion ?? "N/A";
        properties.Add("version", ver);
        var hostName = System.Net.Dns.GetHostName();
        var ips = await System.Net.Dns.GetHostAddressesAsync(hostName);
        var ipa = ips.First().MapToIPv4().ToString() ?? "N/A";
        properties.Add("ip-address", ipa);
        return properties;
    }

}
