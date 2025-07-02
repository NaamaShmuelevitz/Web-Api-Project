using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using Entities;
using Services;
using DTO;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authorization;
// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace MyShop.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        IUserService _userServices;
        IMapper _mapper;
        ILogger<UsersController> _logger;
        IJwtService _jwtService;

        public UsersController(IUserService userServices, IMapper mapper, ILogger<UsersController> logger, IJwtService jwtService)
        {
            _userServices = userServices;
            _mapper = mapper;
            _logger = logger;
            _jwtService = jwtService;
        }

        // GET api/<UsersController>/5
        [HttpGet("{id}")]
        public async Task<GetUserDTO> Get(int id)
        {
            User user = await _userServices.GetById(id);
            return _mapper.Map<User, GetUserDTO>(user);
        }

        // POST api/<UsersController>
        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public async Task<ActionResult<User>> Login([FromQuery] string userName, [FromQuery] string password)
        {
            _logger.LogInformation("Login attempt for user: {UserName}", userName);
            User checkUser = await _userServices.LoginUser(userName, password);
            if (checkUser != null)
            {
                _logger.LogInformation("User {UserId} logged in successfully", checkUser.UserId);
                // Generate JWT token after successful login
                var token = _jwtService.GenerateToken(checkUser);
                Response.Cookies.Append("jwtToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true, // Set to true in production
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddMinutes(60)
                });
                return Ok(checkUser);
            }
            _logger.LogWarning("Login failed for user: {UserName}", userName);
            return BadRequest("Invalid username or password");
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult<User>> Register([FromBody] RegisterUserDTO registerUserDTO)
        {
            try
            {
                User user = _mapper.Map<RegisterUserDTO, User>(registerUserDTO);
                User userRegister = await _userServices.RegisterUser(user);
                if (userRegister != null)
                {
                    return Ok(_mapper.Map<User, GetUserDTO>(userRegister));
                }
                return BadRequest();
            }
            catch (Exception ex)
            {
                return Conflict(new { message = "Weak password" });
            }
        }

        [HttpPost]
        [Route("password")]
        public int CheckPassword([FromBody] String password)
        {
            return _userServices.CheckPassword(password);
        }

        // PUT api/<UsersController>/5
        [HttpPut("{id}")]
        public async Task<ActionResult<User>> Put(int id, [FromBody] RegisterUserDTO userToUpdateDTO)
        {
            try { 
            User user = _mapper.Map<RegisterUserDTO, User>(userToUpdateDTO);
            User userUpdate =await _userServices.UpdateUser(id, user);
            if (userUpdate != null)
            {
                return Ok(_mapper.Map<User, GetUserDTO>(userUpdate));
            }
            return BadRequest();
            }
             catch (Exception ex)
            {
                return Conflict(new { message = "Weak password" });
            }
        }
    }
}
