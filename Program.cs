using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add a secret key to the configuration.
builder.Configuration["Jwt:Key"] = "ThisIsASecretKeyForJwtLearningDemo"; // Replace with a secure key.

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "JwtDemoApp", // Must match "iss" in the token.
            ValidAudience = "JwtDemoApp", // Must match "aud" in the token.
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"] ?? "DefaultFallbackKey"))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/generate-token", (string username) =>
{
    if (string.IsNullOrWhiteSpace(username))
    {
        return Results.BadRequest("Username is required.");
    }

    // Retrieve the secret key from configuration.
    var secretKey = builder.Configuration["Jwt:Key"];
    if (string.IsNullOrEmpty(secretKey))
    {
        return Results.BadRequest("Secret key not configured.");
    }

    // Generate a token using JwtHelper.
    var token = JwtHelper.GenerateToken(username, secretKey);

    return Results.Ok(new { Token = token });
});

app.MapPost("/decode-token", (string token) =>
{
    if (string.IsNullOrWhiteSpace(token))
    {
        return Results.BadRequest("Token is required.");
    }

    try
    {
        // Decode the token using JwtHelper.
        var claims = JwtHelper.DecodeToken(token);
        return Results.Ok(claims);
    }
    catch (Exception ex)
    {
        return Results.BadRequest($"Error decoding token: {ex.Message}");
    }
});

app.MapGet("/secure-data", () =>
{
    return Results.Ok(new { Message = "This is secured data!" });
}).RequireAuthorization();

app.Run();
