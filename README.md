# Impersonate

I found a description of how to impersonate another user at <a href="http://tech.trailmax.info/2014/06/user-impersonation-with-asp-net-identity-2/">User impersonation with ASP.Net Identity 2</a>. I didn't really like the solution to get a source file from Codeplex and modify it so that claims are readded when the identity is regenerated. My solution is to modify the ApplicationUser.GenerateUserIdentityAsync() method instead to re-add impersonation claims there.

