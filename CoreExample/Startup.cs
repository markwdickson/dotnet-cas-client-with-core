using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CoreExample.Middleware;
using DotNetCoreCas;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CoreExample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            var scheme = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;

            services.AddAuthentication(scheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Cas/Login";
                    options.LogoutPath = "/Cas/Logout";
                    options.AccessDeniedPath = "/Home/UnauthorizedUser";
                    options.Cookie.Name = ".CasAuth";
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    //The url parameter "redirect" is used for CAS. This will
                    //need to be set if you try to call it another way.
                    options.ReturnUrlParameter = "redirect";
                });

            //To use more than one authentication provider you will need to set the LoginPath to /Home/Login instead of /Cas/Login
            //services.AddAuthentication(scheme)
            //       .AddCookie(options =>
            //       {
            //           options.LoginPath = "/Home/Login";
            //           options.LogoutPath = "/Home/Logout";
            //           options.AccessDeniedPath = "/Home/UnauthorizedUser";
            //           options.Cookie.Name = ".CasAuth";
            //           options.Cookie.SameSite = SameSiteMode.Strict;
            //       });


            //Gets the CasOptions from appsettings.json (you can put your own in secrets.json to override this)
            var casOptions = Configuration.GetSection("CasOptions").Get<CasOptions>();
            casOptions.AuthenticationScheme = scheme;

            services.AddCas(casOptions);

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseAuthentication();

            app.UseCas<MyCasMiddleware>();
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
