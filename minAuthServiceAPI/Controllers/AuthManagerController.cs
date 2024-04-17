using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Models;

namespace Controllers;

[ApiController]
[Route("[controller]")]
public class AuthManagerController : ControllerBase
{
    private readonly ILogger<AuthManagerController> _logger;
    private readonly IConfiguration _config;

    public AuthManagerController(ILogger<AuthManagerController> logger, IConfiguration config)
    {
        _config = config;
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


    private string GenerateJwtToken(string username)
    {
        // her tager den fra environment variablerne fra compose filen  og ikke vault
        var securityKey =
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("Secret")));
        var credentials =
        new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
new Claim(ClaimTypes.NameIdentifier, username)
};
        //endnu en secret i compose filen, lav den med vault til projekt
        var token = new JwtSecurityToken(
        Environment.GetEnvironmentVariable("Issuer"),
        "http://localhost",
        claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // fix if statement senere her
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        if (login.Username == "haavy_user" && login.Password == "aaakodeord")
        {
            var token = GenerateJwtToken(login.Username);
            return Ok(new { token });
        }
        return Unauthorized();
    }

}
