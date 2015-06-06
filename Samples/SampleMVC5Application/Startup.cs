using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SampleMVC5Application.Startup))]
namespace SampleMVC5Application
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
