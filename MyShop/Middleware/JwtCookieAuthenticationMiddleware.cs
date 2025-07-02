using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MyShop.Middleware
{
    public class JwtCookieAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string _jwtKey;
        private readonly string _jwtIssuer;

        // Add null checks for configuration values in the constructor
        public JwtCookieAuthenticationMiddleware(RequestDelegate next, IConfiguration config)
        {
            _next = next;
            _jwtKey = config["Jwt:Key"] ?? throw new ArgumentNullException("Jwt:Key", "JWT Key is missing in configuration.");
            _jwtIssuer = config["Jwt:Issuer"] ?? throw new ArgumentNullException("Jwt:Issuer", "JWT Issuer is missing in configuration.");
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value?.ToLower();
            if (path != null && (path.Contains("/login") || path.Contains("/register")))
            {
                await _next(context);
                return;
            }

            var token = context.Request.Cookies["jwtToken"];
            if (!string.IsNullOrEmpty(token))
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_jwtKey);

                try
                {
                    var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = true,
                        ValidIssuer = _jwtIssuer,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero
                    }, out _);

                    context.User = principal;
                }
                catch
                {
                    // Invalid token: context.User remains unauthenticated
                }
            }
            await _next(context);
        }
    }

    public static class JwtCookieAuthenticationMiddlewareExtensions
    {
        public static WebApplication UseJwtCookieAuthentication(this WebApplication app)
        {
            app.UseMiddleware<JwtCookieAuthenticationMiddleware>();
            return app;
        }
    }
}