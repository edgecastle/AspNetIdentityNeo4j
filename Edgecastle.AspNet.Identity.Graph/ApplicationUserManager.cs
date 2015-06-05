using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Neo4jClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Graph
{
	/// <summary>
	/// Manager for users backed by a graph database store
	/// </summary>
	public class ApplicationUserManager : UserManager<ApplicationUser>
	{
		private readonly GraphClient DB;

		/// <summary>
		/// Initializes a new instance of the <see cref="ApplicationUserManager"/> class.
		/// </summary>
		/// <param name="store"></param>
		public ApplicationUserManager(IUserStore<ApplicationUser> store)
			: base(store)
		{
            
			DB = new GraphDBProvider().GetClient();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="options"></param>
		/// <param name="context"></param>
		/// <returns></returns>
		public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
		{
			ApplicationUserManager manager = new ApplicationUserManager(new UserStore());

			// Username rules
			manager.UserValidator = new UserValidator<ApplicationUser>(manager)
			{
				AllowOnlyAlphanumericUserNames = false,
				RequireUniqueEmail = true
			};

			// Password rules
			manager.PasswordValidator = new PasswordValidator
			{
				RequiredLength = 6,
				RequireNonLetterOrDigit = true,
				RequireDigit = true,
				RequireLowercase = true,
				RequireUppercase = true
			};

			// Configure lockouts
			manager.UserLockoutEnabledByDefault = true;
			manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
			manager.MaxFailedAccessAttemptsBeforeLockout = 5;

			// Two-factor authentication
			manager.RegisterTwoFactorAuthProviders();

			var dataProtectionProvider = options.DataProtectionProvider;
			if (dataProtectionProvider != null)
			{
				manager.UserTokenProvider =
					new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("Edgecastle ASP.NET Graph Identity"));
			}

			return manager;
		}

		/// <summary>
		/// Configures two-factor authentication (2FA) providers
		/// </summary>
		protected virtual void RegisterTwoFactorAuthProviders()
		{
			// Add two factor authentication providers here, or derive from this class and override
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public override async Task<IdentityResult> CreateAsync(ApplicationUser user, string password)
		{
			IdentityResult createResult = null;

			user.PasswordHash = base.PasswordHasher.HashPassword(password);

			// Cleanses and sets up properties on user object ready for commit to the DB
			user.SanitizeNewUser();
			
			var matchString = String.Format("(existingUser:{0} {{ Username: {{user}}.UserName }})", Configuration.Global.UserLabel);

			var matchedUsers = (await DB.Cypher
										.Match(matchString)
										.WithParam("user", user)
										.Return(existingUser => existingUser.Count())
										.ResultsAsync)
										.Single();										

			if(matchedUsers != 0)
			{
				// User already exists
				// TODO: Globalize
				createResult = new IdentityResult("User already exists.");
			}
			else
			{
				var createString = String.Format("(newUser:{0} {{newUser}})", Configuration.Global.UserLabel);

				await DB.Cypher
						.Create(createString)
						.WithParam("newUser", user)
						.ExecuteWithoutResultsAsync();

				createResult = IdentityResult.Success;
			}

			return createResult;
		}
	}
}
