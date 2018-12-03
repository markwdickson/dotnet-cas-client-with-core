using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CoreExample.Controllers
{
    public class AuthController : Controller
    {
        [Authorize(AuthenticationSchemes = "CAS")]
        public IActionResult Login(string ReturnUrl)
        {
            //if (!User.Identity.IsAuthenticated)
            //{
            //    var test = HttpContext.Request.PathBase.HasValue ? HttpContext.Request.PathBase.Value : "";
            //    return LocalRedirect(test + "/Cas/Login" + (HttpContext.Request.QueryString.HasValue ? HttpContext.Request.QueryString.Value.Replace(nameof(ReturnUrl), "redirect") : ""));
            //}

            var claims = new List<Claim> { new Claim(ClaimTypes.Name, HttpContext.User.Identity.Name) };

            var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
            return SignIn(new ClaimsPrincipal(claimsIdentity), "Cookies");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync("Cookies");

            return RedirectToAction("Logout", "CAS");
        }
    }
}