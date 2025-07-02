using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using MyShop;
using MyShop.Middleware;
using NLog.Web;
using PresidentsApp.Middlewares;
using Repositories;
using Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

//builder.Services.AddDbContext<MyShop215736745Context>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("School")));
builder.Services.AddDbContext<MyShop215736745Context>(options =>
   options.UseSqlServer(builder.Configuration.GetConnectionString("Home")));

builder.Services.AddTransient<IUsersRepository,UsersRepository>();

builder.Services.AddTransient<IUserService, UserService>();


builder.Services.AddTransient<IProductsRepository, ProductsRepository>();

builder.Services.AddTransient<IProductsService, ProductsService>();


builder.Services.AddTransient<ICategoriesRepository, CategoriesRepository>();

builder.Services.AddTransient<ICategoriesService, CategoriesService>();


builder.Services.AddTransient<IOrdersRepository, OrdersRepository>();

builder.Services.AddTransient<IOrdersService, OrdersService>();


builder.Services.AddTransient<IRatingRepository, RatingRepository>();

builder.Services.AddTransient<IRatingService, RatingService>();

builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

builder.Host.UseNLog();

builder.Services.AddMemoryCache();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen();

builder.Services.AddTransient<IJwtService, JwtService>();

var app = builder.Build();

// Configure the HTTP request pipeline.

if(app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseErrorHandlingMiddleware();

app.UseRatingMiddleware();

app.UseHttpsRedirection();

app.UseAuthorization();

app.UseStaticFiles();

// Add JWT authentication middleware before authorization
app.UseJwtCookieAuthentication();

app.MapControllers();

app.Run();
