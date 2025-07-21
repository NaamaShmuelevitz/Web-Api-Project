using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace MyShop.Middleware
{
    public class CspMiddleware
    {
        private readonly RequestDelegate _next;
        public CspMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            
            context.Response.Headers.Add("Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;");
            await _next(context);
        }
    }

    public static class CspMiddlewareExtensions
    {
        public static IApplicationBuilder UseCspMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<CspMiddleware>();
        }
    }
}
