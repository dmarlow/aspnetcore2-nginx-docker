using BearerTokenBridge;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Api.Auth
{
    // This is fun.. https://stackoverflow.com/questions/31464359/how-do-you-create-a-custom-authorizeattribute-in-asp-net-core
    public abstract class AttributeAuthorizationHandler<TRequirement, TAttribute> : AuthorizationHandler<TRequirement> where TRequirement : IAuthorizationRequirement where TAttribute : Attribute
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement)
        {
            var attributes = new List<TAttribute>();

            var action = (context.Resource as AuthorizationFilterContext)?.ActionDescriptor as ControllerActionDescriptor;
            if (action != null)
            {
                attributes.AddRange(GetAttributes(action.ControllerTypeInfo.UnderlyingSystemType));
                attributes.AddRange(GetAttributes(action.MethodInfo));
            }

            return HandleRequirementAsync(context, requirement, attributes);
        }

        protected abstract Task HandleRequirementAsync(AuthorizationHandlerContext context, TRequirement requirement, IEnumerable<TAttribute> attributes);

        private static IEnumerable<TAttribute> GetAttributes(MemberInfo memberInfo)
        {
            return memberInfo.GetCustomAttributes(typeof(TAttribute), false).Cast<TAttribute>();
        }
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    public class PermissionAttribute : AuthorizeAttribute
    {
        public string Name { get; }

        public PermissionAttribute(string name) : base("Permission")
        {
            AuthenticationSchemes = "Degreed";
            Name = name;
        }
    }
    public class PermissionAuthorizationRequirement : IAuthorizationRequirement
    {
        //Add any custom requirement properties if you have them
    }
    public class PermissionAuthorizationHandler : AttributeAuthorizationHandler<PermissionAuthorizationRequirement, PermissionAttribute>
    {
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
            PermissionAuthorizationRequirement requirement, IEnumerable<PermissionAttribute> attributes)
        {
            foreach (var permissionAttribute in attributes)
            {
                if (!await AuthorizeAsync(context.User, permissionAttribute.Name))
                {
                    return;
                }
            }

            context.Succeed(requirement);
        }

        private Task<bool> AuthorizeAsync(ClaimsPrincipal user, string permission)
        {
            var hasClaim = user.Claims.Any(c => c.Type == "urn:oauth:scope" && c.Value == permission);
            return Task.FromResult(hasClaim);
        }
    }
    public class DegreedAuthHandler : AuthenticationHandler<DegreedOAuthOptions>
    {
        private const string Authorization = "Authorization";
        private const string Bearer = "Bearer";
        private readonly IConfiguration _config;

        public DegreedAuthHandler(IConfiguration config, IOptionsMonitor<DegreedOAuthOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
            _config = config;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // grab stuff from the request
            string authHeader = Context.Request.Headers[Authorization];
            if (string.IsNullOrWhiteSpace(authHeader))
            {
                Logger.LogDebug("Authorization header missing.");
                return Task.FromResult(AuthenticateResult.Fail("'Authorization' header missing"));
            }

            // Ensure that the authorization header contains the mandatory "Bearer" scheme.
            // See https://tools.ietf.org/html/rfc6750#section-2.1
            if (!authHeader.StartsWith("Bearer" + ' ', StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogDebug("Authentication was skipped because an incompatible " +
                                "scheme was used in the 'Authorization' header.");

                return Task.FromResult(AuthenticateResult.Fail("Invalid 'Authorization' header."));
            }
            var token = authHeader.Substring(Bearer.Length + 1).Trim();

            if (string.IsNullOrEmpty(token))
            {
                Logger.LogDebug("Authentication was skipped because the bearer token " +
                                "was missing from the 'Authorization' header.");

                return Task.FromResult(AuthenticateResult.Fail("Bearer token not specified."));
            }

            string validationKey = _config.GetValue<string>("ValidationKey");
            string decryptionKey = _config.GetValue<string>("DecryptionKey");
            var ticket = MachineKeyOwinBearerAuthTicketUnprotector.Unprotect(token, decryptionKey, validationKey);

            var newTicket = MachineKeyOwinBearerAuthTicketUnprotector.Convert(ticket, "Degreed");

            var result = AuthenticateResult.Success(newTicket);
            return Task.FromResult(result);
        }
    }

    public class DegreedOAuthOptions : AuthenticationSchemeOptions
    {
    }

    public static class DegreedMiddlewareAppBuilderExtensions
    {
        public static AuthenticationBuilder AddDegreedAuth(this AuthenticationBuilder builder, Action<DegreedOAuthOptions> configureOptions = null)
        {
            return builder.AddScheme<DegreedOAuthOptions, DegreedAuthHandler>("Degreed", "Degreed OAuth", configureOptions);
        }
    }
}
