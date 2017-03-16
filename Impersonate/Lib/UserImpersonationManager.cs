using Impersonate.Constants;
using Impersonate.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Web;

namespace Impersonate.Lib
{
    //
    // Implementation found at: http://tech.trailmax.info/2014/06/user-impersonation-with-asp-net-identity-2/
    // Katana/OWIN source code: https://katanaproject.codeplex.com/
    // Identity 2 source code:  https://aspnetidentity.codeplex.com/
    //
    public class UserImpersonationManager
    {
        protected ApplicationUserManager userManager = new ApplicationUserManager(new UserStore<ApplicationUser>(new ApplicationDbContext()));

        public async Task ImpersonateUserAsync(string userName)
        {
            var context = HttpContext.Current;

            var originalUsername = context.User.Identity.Name;

            var impersonatedUser = await userManager.FindByNameAsync(userName);

            // Use ApplicationSigninManager.CreateUserIdentityAsync() so that ApplicationUser.GenerateUserIdentityAsync() is called.
            var authenticationManager = context.GetOwinContext().Authentication;
            var signinManager = new ApplicationSignInManager(userManager, authenticationManager);
            var impersonatedIdentity = await signinManager.CreateUserIdentityAsync(impersonatedUser);

            impersonatedIdentity.AddClaim(new Claim("UserImpersonation", "true"));
            impersonatedIdentity.AddClaim(new Claim("OriginalUsername", originalUsername));

            authenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, impersonatedIdentity);
        }

        public async Task RevertImpersonationAsync()
        {
            var context = HttpContext.Current;

            if (!HttpContext.Current.User.IsImpersonating())
            {
                throw new Exception("Unable to remove impersonation because there is no impersonation");
            }

            var originalUsername = HttpContext.Current.User.GetOriginalUsername();

            var originalUser = await userManager.FindByNameAsync(originalUsername);

            // Use ApplicationSigninManager.CreateUserIdentityAsync() so that ApplicationUser.GenerateUserIdentityAsync() is called.
            var authenticationManager = context.GetOwinContext().Authentication;
            var signinManager = new ApplicationSignInManager(userManager, authenticationManager);
            var impersonatedIdentity = await signinManager.CreateUserIdentityAsync(originalUser);

            authenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, impersonatedIdentity);
        }
    }
}