using DotNetCoreCas;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace CoreExample.Middleware
{
    public class MyCasMiddleware : CasMiddleware
    {
        public MyCasMiddleware(RequestDelegate next, ICasOptions options) : base(next, options)
        {
        }

        protected override List<Claim> GetClaims(string username) => new List<Claim> { new Claim(ClaimTypes.Name, username + "override") };
    }
}
