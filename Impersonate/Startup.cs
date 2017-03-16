using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Impersonate.Startup))]
namespace Impersonate
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
