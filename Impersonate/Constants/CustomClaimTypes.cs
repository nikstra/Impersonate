using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Impersonate.Constants
{
    public static class CustomClaimTypes
    {
        public const string OriginalUsername = "OriginalUsername";
        public const string Persistent = "ClaimPersistent";
        public const string UserImpersonation = "UserImpersonation";
        public const string Volatile = "ClaimVolatile";
    }
}