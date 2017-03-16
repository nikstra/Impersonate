using Impersonate.Constants;
using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace Impersonate.Lib
{
    //
    // Implementation found at: http://tech.trailmax.info/2014/06/user-impersonation-with-asp-net-identity-2/
    //
    public static class ClaimsPrincipalExtensions
    {
        public static bool IsImpersonating(this IPrincipal principal)
        {
            if (principal == null)
            {
                return false;
            }

            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return false;
            }

            return claimsPrincipal.HasClaim(AuthConstants.ClaimUserImpersonation, "true");
        }

        public static String GetOriginalUsername(this IPrincipal principal)
        {
            if (principal == null)
            {
                return String.Empty;
            }

            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                return String.Empty;
            }

            if (!claimsPrincipal.IsImpersonating())
            {
                return String.Empty;
            }

            var originalUsernameClaim = claimsPrincipal.Claims.SingleOrDefault(c => c.Type == AuthConstants.ClaimOriginalUsername);

            if (originalUsernameClaim == null)
            {
                return String.Empty;
            }

            return originalUsernameClaim.Value;
        }

        public static string GetVolatileClaim(this IPrincipal principal)
        {
            if (principal == null) return null;

            return (principal as ClaimsPrincipal).Claims
                .SingleOrDefault(c => c.Type == AuthConstants.ClaimVolatile)?.Value;
        }

        public static string GetPersistentClaim(this IPrincipal principal)
        {
            if (principal == null) return null;

            return (principal as ClaimsPrincipal).Claims
                .SingleOrDefault(c => c.Type == AuthConstants.ClaimPersistent)?.Value;
        }

        // Get the OrganizationId parsed to an int.
        public static int? GetOrganizationId(this IPrincipal principal)
        {
            if (principal == null) return null;

            string organizationId = (principal as ClaimsPrincipal).Claims
                .SingleOrDefault(c => c.Type == AuthConstants.ClaimPersistent)?.Value;

            int orgId;
            return int.TryParse(organizationId, out orgId) ? (int?)orgId : null;
        }

        public static bool HasAccessToStudio(this IPrincipal principal, int studioId)
        {
            if (principal == null) return false;

            return (principal as ClaimsPrincipal).Claims
                .Any(c => c.Type == AuthConstants.ClaimVolatile && c.Value == studioId.ToString());
        }
    }
}
