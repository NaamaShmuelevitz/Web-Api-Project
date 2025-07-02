using Repositories;
using Entities;
using Zxcvbn;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace Services;

public class UserService : IUserService
{
    IUsersRepository _userRepository;
    private readonly IConfiguration _configuration;

    public UserService(IUsersRepository userRepository, IConfiguration configuration)
    {
        _userRepository = userRepository;
        _configuration = configuration;
    }
    public async Task<User> LoginUser(string userName, string password)
    {
        return await _userRepository.LoginUser(userName, password);
    }

    public async Task<User> GetById(int id)
    {
        return await _userRepository.GetById(id);
    }

    public async Task<User> RegisterUser(User user)
    {
        var checkPasswordResult = CheckPassword(user.Password);
        if (checkPasswordResult < 2)
        {
            throw new Exception("Weak password");
        }
        return await _userRepository.Register(user);
    }

    public async Task<User> UpdateUser(int id, User user)
    {
        var result = CheckPassword(user.Password);
        if (result < 2)
        {
            throw new Exception("Weak password");
        }
        return await _userRepository.UpdateUser(id, user);
    }
   
    public int CheckPassword(string password)
    {
        return Zxcvbn.Core.EvaluatePassword(password).Score;
    }

    // Add a method to generate JWT tokens in the UserService
    public string GenerateToken(User user)
    {
        var jwtKey = _configuration["Jwt:Key"];
        var jwtIssuer = _configuration["Jwt:Issuer"];

        if (string.IsNullOrEmpty(jwtKey) || string.IsNullOrEmpty(jwtIssuer))
        {
            throw new Exception("JWT key or issuer is missing in configuration");
        }

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
            new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, user.UserId.ToString()),
            new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Email, user.UserName)
        };

        var token = new JwtSecurityToken(
            issuer: jwtIssuer,
            audience: null,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(60),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
