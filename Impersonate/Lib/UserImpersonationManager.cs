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
            var originalUsername = HttpContext.Current.User.Identity.Name;
            var impersonatedUser = await userManager.FindByNameAsync(userName);
            await SwitchUser(impersonatedUser, originalUsername);
        }

        public async Task RevertImpersonationAsync()
        {
            if (!HttpContext.Current.User.IsImpersonating())
            {
                throw new Exception("Unable to remove impersonation because there is no impersonation");
            }

            var originalUsername = HttpContext.Current.User.GetOriginalUsername();
            var originalUser = await userManager.FindByNameAsync(originalUsername);
            await SwitchUser(originalUser);
        }

        private async Task SwitchUser(ApplicationUser user, string originalUsername = null)
        {
            // Use ApplicationSigninManager.CreateUserIdentityAsync() so that ApplicationUser.GenerateUserIdentityAsync() is called.
            var context = HttpContext.Current.GetOwinContext();
            var signinManager = context.Get<ApplicationSignInManager>();
            var claimsIdentity = await signinManager.CreateUserIdentityAsync(user);

            // Only add claims when we start impersonation.
            if(!string.IsNullOrEmpty(originalUsername))
            {
                claimsIdentity.AddClaim(new Claim(CustomClaimTypes.UserImpersonation, "true"));
                claimsIdentity.AddClaim(new Claim(CustomClaimTypes.OriginalUsername, originalUsername));
            }

            var authenticationManager = context.Authentication;
            authenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, claimsIdentity);
        }
    }
}