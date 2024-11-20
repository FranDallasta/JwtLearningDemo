using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public static class JwtHelper
{
    public static string GenerateToken(string username, string secretKey)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        // Define token claims (e.g., username).
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Create the token.
        var token = new JwtSecurityToken(
            issuer: "JwtDemoApp",
            audience: "JwtDemoApp",
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: credentials
        );

        // Return the serialized token.
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static IDictionary<string, object> DecodeToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        // Validate if the token is readable.
        if (!handler.CanReadToken(token))
        {
            throw new ArgumentException("Invalid JWT token.");
        }

        // Decode the token without validation.
        var jwtToken = handler.ReadJwtToken(token);

        // Extract claims as key-value pairs.
        var claims = jwtToken.Claims.ToDictionary(c => c.Type, c => (object)c.Value);

        return claims;
    }
}

