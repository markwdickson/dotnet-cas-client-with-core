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

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using DotNetCoreCas.Logging;
using DotNetCoreCas.Security;
using DotNetCoreCas.Utils;
using DotNetCoreCas.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace DotNetCoreCas
{
    public class CasMiddleware
    {
        private static readonly Logger logger = new Logger(Category.HttpModule);
        private static readonly Logger configLogger = new Logger(Category.Config);
        private static readonly Logger protoLogger = new Logger(Category.Protocol);
        private static readonly Logger securityLogger = new Logger(Category.Security);

        private readonly ICasOptions _options;
        public CasMiddleware(RequestDelegate next, ICasOptions options)
        {
            options.Validate();
            _options = options;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (_options.TicketValidator.UrlSuffix == null)
            {
                //Need to initiallize the ticket validator.
                //Should find a better way to do this on-create
                _options.TicketValidator.Initialize(context, _options);
            }

            if (context.Request.Path.Value.StartsWith("/Cas/Login"))
            {
                HttpRequest request = context.Request;
                if (!Utils.RequestEvaluator.GetRequestIsAppropriateForCasAuthentication(context, _options))
                {
                    logger.Debug("AuthenticateRequest bypassed for " + request.Path.ToUriComponent());
                    context.Response.Redirect(_options.NotAuthorizedUrl);
                }

                if (Utils.RequestEvaluator.GetRequestHasCasTicket(context, _options))
                {
                    logger.Info("Processing proxy Callback request");
                    var principal = ProcessTicketValidation(context);
                    var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, principal.Identity.Name),
                    new Claim(ClaimTypes.Role, "Test")
                };
                    var claimsIdentity = new ClaimsIdentity(
                        claims, _options.AuthenticationScheme);

                    EnhancedUriBuilder ub = new EnhancedUriBuilder();
                    ub.Path = context.Request.Query["redirect"].ToString();
                    ub.Query = context.Request.QueryString.ToString();
                    ub.QueryItems.Remove("redirect");
                    ub.QueryItems.Remove("ticket");
                    
                    context.Response.Redirect(ub.Uri.PathAndQuery);
                    await context.SignInAsync(_options.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
                }
                else
                {
                    context.Response.Redirect(UrlUtil.ConstructLoginRedirectUrl(context, _options));
                }
            }
            else
            {
                await context.SignOutAsync(_options.AuthenticationScheme);
            }
        }

        public ICasPrincipal ProcessTicketValidation(HttpContext context)
        {
            HttpRequest request = context.Request;

            CasAuthenticationTicket casTicket;
            ICasPrincipal principal = null;

            string ticket = request.Query[_options.TicketValidator.ArtifactParameterName];

            try
            {
                // Attempt to authenticate the ticket and resolve to an ICasPrincipal
                principal = _options.TicketValidator.Validate(context, ticket, _options);

                // Save the ticket in the FormsAuthTicket.  Encrypt the ticket and send it as a cookie. 
                casTicket = new CasAuthenticationTicket(
                    ticket,
                    UrlUtil.RemoveCasArtifactsFromUrl(request.rawUrl(_options).AbsoluteUri, _options),
                    request.Host.Host,
                    principal.Assertion
                );

                if (_options.ProxyTicketManager != null && !string.IsNullOrEmpty(principal.ProxyGrantingTicket))
                {
                    casTicket.ProxyGrantingTicketIou = principal.ProxyGrantingTicket;
                    casTicket.Proxies.AddRange(principal.Proxies);
                    string proxyGrantingTicket = _options.ProxyTicketManager.GetProxyGrantingTicket(casTicket.ProxyGrantingTicketIou);
                    if (!string.IsNullOrEmpty(proxyGrantingTicket))
                    {
                        casTicket.ProxyGrantingTicket = proxyGrantingTicket;
                    }
                }

                return principal;
            }
            catch (TicketValidationException e)
            {
                // Leave principal null.  This might not have been a CAS service ticket.
                protoLogger.Error("Ticket validation error: " + e);
            }
            return null;
        }
    }
}