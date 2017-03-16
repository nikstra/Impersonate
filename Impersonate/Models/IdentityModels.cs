using System.Data.Entity;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Impersonate.Constants;
using System;

namespace Impersonate.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser
    {
        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager, ClaimsIdentity previousIdentity = null)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here

            // Use a presistent claim as value for a volatile claim for demonstration purposes.
            string persistentClaim = userIdentity?.FindFirstValue(AuthConstants.ClaimPersistent);
            userIdentity.AddClaim(new Claim(AuthConstants.ClaimVolatile, string.Format("Volatile, {0}: {1}", DateTime.Now, persistentClaim)));

            // Keep claim when impersonating using UserImpersonationManager.
            if (previousIdentity?.FindFirstValue(AuthConstants.ClaimUserImpersonation) == "true")
            {
                // need to preserve impersonation claims
                userIdentity.AddClaim(new Claim(AuthConstants.ClaimUserImpersonation, "true"));
                userIdentity.AddClaim(previousIdentity.FindFirst(AuthConstants.ClaimOriginalUsername));
            }
            else
            {
                userIdentity.AddClaim(new Claim(AuthConstants.ClaimUserImpersonation, "false"));
            }

            return userIdentity;
        }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
            //Database.SetInitializer<ApplicationDbContext>(new DropCreateDatabaseAlways<ApplicationDbContext>());
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }
}