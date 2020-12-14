using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using secure_API_final_project.CustompolicyProvider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace secure_API_final_project.Controllers
{
    public class SecurityLevelAttribute : AuthorizeAttribute
    {
        public SecurityLevelAttribute(int level)
        {
            Policy = $"{DynamicPolicies.SecurityLevel}.{level}";
        }
    }
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [Authorize] //guard
        public IActionResult Secret()
        {
            return View();
        }
        [Authorize(Policy = "Claim.DoB")]
       
    public IActionResult SecretPolicy() 
        {
            return View("Secret");
        }

        [Authorize(Roles = "Admin")]
        public IActionResult SecretRole()
        {
            return View("Secret");
        }
        [SecurityLevel(5)]
        public IActionResult SecretLevel()
        {
            return View("Secret");
        }

        [SecurityLevel(10)]
        public IActionResult SecretHigherLevel()
        {
            return View("Secret");
        }
        [AllowAnonymous]
        public IActionResult Authenticate()
        {
            var secretClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,"Karishma"),
                new Claim(ClaimTypes.Email,"karishma2792@gmail.com"),
                new Claim(ClaimTypes.DateOfBirth,"27/07/1992"),
                new Claim(ClaimTypes.Role,"AdminTwo"),
                new Claim(ClaimTypes.Role,"Admin"),
                new Claim(DynamicPolicies.SecurityLevel,"7"),
                new Claim("Secret.Says","Very nice girl."),
            };
            var licenseClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,"Karishma Shah"),
                new Claim("Drivinglicense","A+"),
            };
            var secretIdentity = new ClaimsIdentity(secretClaims, "Secret Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaims, "Government");
            
            var userPrincipal = new ClaimsPrincipal(new[] { secretIdentity });

            HttpContext.SignInAsync(userPrincipal);

            
            return RedirectToAction("Index");
        }
        public async Task<IActionResult> Dostuff(
            [FromServices] IAuthorizationService authorizationService)
        {
            // we are doing stuff here
            var builder = new AuthorizationPolicyBuilder("Schema");
            var customPolicy = builder.RequireClaim("Hello").Build();
            var authResult = await authorizationService.AuthorizeAsync(User, customPolicy);
            
            if(authResult.Succeeded)
            {
                return View("Index");
            }
            return View("Index");
        }
    }
}
