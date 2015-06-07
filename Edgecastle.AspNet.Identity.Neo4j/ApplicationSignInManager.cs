using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Neo4j
{
	/// <summary>
	/// Manages sign in operations
	/// </summary>
	public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
	{
		/// <summary>
		/// Creates a new <see cref="ApplicationSignInManager"/>
		/// </summary>
		/// <param name="options">The identity-factory options</param>
		/// <param name="context">The OWIN context</param>
		/// <returns>A new <see cref="ApplicationSignInManager"/></returns>
		public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }

		/// <summary>
		/// Initializes a new instance of the <see cref="ApplicationSignInManager"/> class.
		/// </summary>
		/// <param name="userManager">The user manager</param>
		/// <param name="authenticationManager">The authentication manager</param>
		public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }
	}
}
