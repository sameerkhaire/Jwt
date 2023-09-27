using JwtImplementation.Helpers;
using JwtImplementation.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace JwtImplementation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly jwtuserContext _jwtcontext;
        private readonly IConfiguration _configuration;
        public UserController(jwtuserContext jwtuserContext,IConfiguration configuration)
        {
            _jwtcontext = jwtuserContext;
            _configuration = configuration;
        }
        [Authorize]
        [HttpGet]
        public async Task<List<User>> GetUsers()
        {
            return await _jwtcontext.Users.ToListAsync();
        }
        [HttpPost("Authenticate")]
        public async Task<IActionResult> Login([FromBody] User users)
        {
            if (users == null)
            {
                return BadRequest("users field not valid");
            }
            var user = _jwtcontext.Users.Where(x => x.UserName == users.UserName).FirstOrDefault();
            if (user == null) { return BadRequest("user not found!!"); }
            if (PaaswordHasher.DecryptedPass(user.UserPassword) == users.UserPassword)
            {
                users.Token = CreateJwt(user);
            }
            return Ok(new
            {
                Tokens = users.Token,
                Message = "Login Successfully!!"+" "+ users.FirstName
            });
        }
        [HttpPost("register")]
        public async Task<IActionResult> UserRegister([FromBody] User users)
        {
            if (users == null)
            {
                return BadRequest(new {Message="User is null"});
            }
            if (await CheckUserExist(users.UserName))
                return BadRequest(new { Message = "UserName Already Exists try with different user" });
            if (await CheckEmailExistsAsync(users.EmailAddress))
                return BadRequest(new { Message = "Email Address Already Exists" });
            var passs = CheckPassStrength(users.UserPassword);
            if (passs == null)
            {
                return BadRequest("please enter required password");
            }
               users.UserPassword=PaaswordHasher.HashPassword(users.UserPassword);
              await _jwtcontext.AddAsync(users);
              await _jwtcontext.SaveChangesAsync();

            return Ok(new {Message="hey you have register successfully"+" "+ users.UserName});
            

        }
        private  Task<bool> CheckUserExist(string userName)
            => _jwtcontext.Users.Where(x => x.UserName == userName).AnyAsync();
        private Task<bool> CheckEmailExistsAsync(string email)
            => _jwtcontext.Users.AnyAsync(x => x.EmailAddress == email);
        private string CheckPassStrength(string pass)
        {
            StringBuilder sb = new StringBuilder();
            if (pass.Length < 8)
                sb.Append("password length should be greater than 8"+ Environment.NewLine);
            if (!(Regex.IsMatch(pass, "[a-z]") && Regex.IsMatch(pass, "[A-Z]") && Regex.IsMatch(pass, "[0-9]")))
                sb.Append("Password should be Alpha numeric for ex lower case ,uppercase,Numbers" + Environment.NewLine);
            if(!(Regex.IsMatch(pass, "[`,~,!,@,#,$,%,^,&,*,(,),_,|,+,\\,-,=,?,;,:,',\",.<>,\\,{\\},\\,[\\],\\,\\,\\,/]")))
                sb.Append("Password should contain Special character with it" + Environment.NewLine);
            return sb.ToString();
        }
        private string CreateJwt(User user)
        {
            var Identity = new ClaimsIdentity(new Claim[] {
             new Claim(ClaimTypes.Role,_jwtcontext.Roles.Where(r=>r.RoleId==user.RoleId).FirstOrDefault().RoleName),
              new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}")
            });

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Identity,
                Expires = DateTime.Now.AddDays(1),
                Audience = _configuration["Jwt:Audience"],
                Issuer = _configuration["Jwt:Issuer"],
                SigningCredentials = creds
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return new JwtSecurityTokenHandler().WriteToken(token);

        }

    }
}
