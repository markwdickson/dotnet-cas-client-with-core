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
        /// Adds the CasOptions as a singleton for the MiddleWare to use when setting itself up. This does not enable
        /// authentication in the project. That must be done separately.
        /// </summary>
        /// <param name="services">Object to add the services to</param>
        /// <param name="configureOptions">The options for Cas Authentication. You must enter the required values.</param>
        /// <returns>The services object to allow for chaining</returns>
        public static IServiceCollection AddCas(this IServiceCollection services, ICasOptions configureOptions)
        {
            return services.AddSingleton(configureOptions);
        }

        /// <summary>
        /// Sets the app to map to use the CasMiddleware when the path starts with the casURL
        /// </summary>
        /// <param name="app">The object to add Cas to</param>
        /// <param name="casURL">The 'controller' that is going to hit CAS. This
        /// should be the same 'controller' for the login url of the cookie auth</param>
        /// <returns>The app object to allow for chaining</returns>
        public static IApplicationBuilder UseCas(this IApplicationBuilder app, string casURL = "/Cas/") =>
            app.MapWhen(context => context.Request.Path.Value.StartsWith(casURL, false, null), builder => { builder.UseMiddleware<CasMiddleware>(); });

        /// <summary>
        ///  Sets the app to map to use the CasMiddleware when the path starts with the casURL
        /// </summary>
        /// <typeparam name="T">The type of CasMiddleware that the user wants to use</typeparam>
        /// <param name="app">The object to add Cas to</param>
        /// <param name="casURL">The 'controller' that is going to hit CAS. This
        /// should be the same 'controller' for the login url of the cookie auth</param>
        /// <returns></returns>
        public static IApplicationBuilder UseCas<T>(this IApplicationBuilder app, string casURL = "/Cas/") where T : CasMiddleware =>
            app.MapWhen(context => context.Request.Path.Value.StartsWith(casURL, false, null), builder => { builder.UseMiddleware<T>(); });
    }
}