using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace WebApi.Controllers;
[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
   
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration,ILogger<AuthController> logger)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [HttpPost]
    public async Task<IActionResult> Authenticate([FromBody] Credential credential)
    {
        if (credential.UserName == "admin" && credential.Password == "password")
        {
            // Creating the security context
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "admin"),
                new Claim(ClaimTypes.Email, "admin@mywebsite.com"),
                new Claim("Department", "HR"),
                new Claim("Admin", "true"),
                new Claim("Manager", "true"),
                new Claim("EmploymentDate", "2025-01-01")
            };
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);

            return Ok(
                new
                {
                    access_token = CreateToken(claims, expiresAt),
                    expires_at = expiresAt
                }
            );
        }
        return Unauthorized();
    }

    private object CreateToken(List<Claim> claims, DateTimeOffset expiresAt)
    {
        var issuer = _configuration["Jwt:Issuer"];
        var audience = _configuration["Jwt:Audience"];
        var key = _configuration["Jwt:Key"]; // >= 32 chars recommended
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key!));
        var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expiresAt.UtcDateTime,
            signingCredentials: creds
        );
        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return new
        {
            access_token = jwt,
            token_type = "Bearer",
            expires_at = expiresAt
        };
    }
}


public class Credential
{
    public string Password { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
}