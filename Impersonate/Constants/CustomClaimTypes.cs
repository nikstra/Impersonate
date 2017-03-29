using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Impersonate.Constants
{
    public static class CustomClaimTypes
    {
        public const string OriginalUsername = "http://github.com/nikstra/identity/claims/originalusername";
        public const string Persistent = "http://github.com/nikstra/identity/claims/claimpersistent";
        public const string UserImpersonation = "http://github.com/nikstra/identity/claims/userimpersonation";
        public const string Volatile = "http://github.com/nikstra/identity/claims/claimvolatile";
    }
}