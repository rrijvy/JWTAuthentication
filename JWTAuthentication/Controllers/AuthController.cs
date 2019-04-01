using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWTAuthentication.Data;
using JWTAuthentication.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager,
                                IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [Route("register")]
        public async Task<ActionResult> InserUser([FromBody] RegisterViewModel model)
        {
            var user = new ApplicationUser
            {
                Email = model.Email,
                UserName = model.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Customer");
            }
            return Ok(new { UserName = user.UserName });
        }

        [Route("login")]
        public async Task<ActionResult> Login([FromBody] LoginViewModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var claim = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName)
                };

                var signinKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SigninKey"]));

                int expiryInMunites = Convert.ToInt32(_configuration["JWT:ExpiryInMunites"]);

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:Site"],
                    audience: _configuration["JWT:Site"],
                    expires: DateTime.UtcNow.AddMinutes(expiryInMunites),
                    signingCredentials: new SigningCredentials(signinKey, SecurityAlgorithms.HmacSha256)
                );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expriration = token.ValidTo
                });
            }
            return Unauthorized();
        }
            
    }
}