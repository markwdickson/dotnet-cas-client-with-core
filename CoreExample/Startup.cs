using DotNetCoreCas;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
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
                options.MinimumSameSitePolicy = SameSiteMode.Strict;
            });

            var casOptions = Configuration.GetSection("CasOptions").Get<CasOptions>() ?? new CasOptions
            {
                AuthenticationScheme = "CAS"
            };

            services.AddAuthentication(casOptions.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Auth/Login";
                    options.LogoutPath = "/Auth/Logout";
                    options.Cookie.Expiration = new System.TimeSpan(3, 0, 0);
                    options.Cookie.SameSite = SameSiteMode.Strict;
                })
                .AddCookie(casOptions.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/Cas/Login";
                    options.LogoutPath = "/Cas/Logout";
                    options.Cookie.Name = "CasAuth";
                    options.Cookie.Expiration = new System.TimeSpan(3, 0, 0);
                    options.Cookie.SameSite = SameSiteMode.Strict;
                    options.ReturnUrlParameter = "redirect";
                });
            services.AddCas(casOptions);

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UsePathBase("/castest");
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseAuthentication();

            app.UseCas();
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
