/*
 * Licensed to Apereo under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Apereo licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace DotNetCoreCas
{
    public static class CasServiceCollectionExtensions
    {
        /// <summary>
        /// Sets up cookie authentication under the specified Authentication Scheme. This will most likely need
        /// to change in the future to allow the user to setup cookie authentication how they want to.
        /// </summary>
        /// <param name="services">Object to add the services to</param>
        /// <param name="configureOptions">The options for Cas Authentication. You must enter the required values.</param>
        /// <returns>The services object to allow for chaining</returns>
        public static IServiceCollection AddCas(this IServiceCollection services, ICasOptions configureOptions)
        {
            services.AddAuthentication(configureOptions.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Cas/Login";
                    options.LogoutPath = "/Cas/Logout";
                    options.AccessDeniedPath = "/Error/UnauthorizedUser";
                    options.Cookie.Name = ".CasAuth";
                    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
                    options.ReturnUrlParameter = "redirect";
                });
            //Adds the CAS options to allow for DI Injection into the middleware
            return services.AddSingleton<ICasOptions>(configureOptions);
        }

        /// <summary>
        /// Sets the app to use authentication and maps it to use the CasMiddleware when the path starts with /Cas/
        /// </summary>
        /// <param name="app">The object to add Cas to</param>
        /// <returns>The app object to allow for chaining</returns>
        public static IApplicationBuilder UseCas(this IApplicationBuilder app) =>
            app.UseAuthentication().MapWhen(context => context.Request.Path.Value.StartsWith("/Cas/"), builder => { builder.UseMiddleware<CasMiddleware>(); });
    }
}