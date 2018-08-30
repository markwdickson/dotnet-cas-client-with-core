using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CoreExample.Controllers
{
    public class AuthController : Controller
    {
        [Authorize(AuthenticationSchemes = "CAS")]
        public IActionResult Login(string RedirectUrl)
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, HttpContext.User.Identity.Name) };

            var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
            return SignIn(new ClaimsPrincipal(claimsIdentity), "Cookies");
        }

        public IActionResult Logout()
        {
            return SignOut("CAS", "Cookies");
        }
    }
}