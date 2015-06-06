using Microsoft.AspNet.Identity;
using Neo4jClient;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Graph
{
	/// <summary>
	/// A user service using a graph database as a backing store
	/// </summary>
	public class UserStore : IUserStore<ApplicationUser>,
								  IUserRoleStore<ApplicationUser>,
								  IUserClaimStore<ApplicationUser>,
							      IUserTwoFactorStore<ApplicationUser, string>, 
								  IUserLoginStore<ApplicationUser>,
								  IUserPasswordStore<ApplicationUser>,
								  IUserEmailStore<ApplicationUser>,
								  IUserLockoutStore<ApplicationUser, string>,
							      IUserPhoneNumberStore<ApplicationUser>
	{
		private GraphClient DB = null;

		/// <summary>
		/// Initializes a new instance of the <see cref="UserStore"/> class.
		/// </summary>
		public UserStore()
		{
            // TODO: Dependency injection of the GraphClient
			this.DB = new GraphClient(new Uri("http://enter-your-neo4j-uri-here/"));
            this.DB.Connect();
		}

		/// <summary>
		/// Returns a user by email address
		/// </summary>
		/// <param name="email">The email address to search for</param>
		/// <returns>The user, if found, or null, if not found.</returns>
		public async Task<ApplicationUser> GetUserByEmailAddress(string email)
		{
			if(string.IsNullOrWhiteSpace(email))
			{
				throw new ArgumentNullException("email");
			}

			var user = (await DB.Cypher
								.Match("(existingUser:User { Email: {email} })")
								.WithParam("email", email.ToLowerInvariant())
								.Return(existingUser => existingUser.As<ApplicationUser>())
								.ResultsAsync).SingleOrDefault();

			return user;
		}

		/// <summary>
		/// Ascertains whether the user already exists (based on the email address)
		/// </summary>
		/// <param name="email">The email address to search for.</param>
		/// <returns>True, if already exists, otherwise false.</returns>
		public async Task<bool> UserAlreadyExists(string email)
		{
			return (await GetUserByEmailAddress(email)) != null;
		}

		/// <summary>
		/// Creates and persists a user to the backing store.
		/// </summary>
		/// <param name="user">The user to save</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public async Task CreateAsync(ApplicationUser user)
		{
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}

			// Cleanses and sets up properties for new users ready to be persisted to the DB
			user.SanitizeNewUser();

			// Create User
			await DB.Cypher
					.Create("(:User {user})")
					.WithParam("user", user)
					.ExecuteWithoutResultsAsync();
		}

		/// <summary>
		/// Deletes a user
		/// </summary>
		/// <param name="user">The user to delete</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public Task DeleteAsync(ApplicationUser user)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Finds a user by their unique identifier
		/// </summary>
		/// <param name="userId">The identifier to search for</param>
		/// <returns>The <see cref="ApplicationUser"/> if found, otherwise null.</returns>
		public async Task<ApplicationUser> FindByIdAsync(string userId)
		{
			if (string.IsNullOrWhiteSpace(userId))
			{
				throw new ArgumentNullException("userId");
			}

			var query = DB.Cypher
								.Match("(identity:User { Id: {userId} })")
								.WithParam("userId", userId)
								.Return(identity => identity.As<ApplicationUser>());

			return (await query.ResultsAsync).SingleOrDefault();
		}

		/// <summary>
		/// Finds a user by the username
		/// </summary>
		/// <param name="userName">The username to search for</param>
		/// <returns>The <see cref="ApplicationUser"/> if found, otherwise null.</returns>
		public async Task<ApplicationUser> FindByNameAsync(string userName)
		{
			if (string.IsNullOrWhiteSpace(userName))
			{
				throw new ArgumentNullException("userName");
			}

			var query = DB.Cypher
								.Match("(identity:User { UserName: {userName} })")
								.WithParam("userName", userName.ToLowerInvariant())
								.Return(identity => identity.As<ApplicationUser>());

			return (await query.ResultsAsync).SingleOrDefault();
		}

		/// <summary>
		/// Updates the user with the new properties
		/// </summary>
		/// <param name="user">The <see cref="ApplicationUser"/> to update</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public async Task UpdateAsync(ApplicationUser user)
		{
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}

			user.LastLogin = DateTimeOffset.UtcNow;

			await DB.Cypher
					.Match("(user:User { Id: {userId} })")
					.WithParam("userId", user.Id)
					.Set("user = {user}")
					.WithParam("user", user)
					.ExecuteWithoutResultsAsync();
		}

		/// <summary>
		/// Disposes all native and managed resources used by this class.
		/// </summary>
		public void Dispose()
		{
			this.Dispose(true);
		}

		/// <summary>
		/// Adds a role to a user account
		/// </summary>
		/// <param name="user">The user account to add the role to</param>
		/// <param name="roleName">The role to add</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public async Task AddToRoleAsync(ApplicationUser user, string roleName)
		{
			await DB.Cypher
				.Match("(user:User { Id: {userId} })-[rel:IN_ROLE]->(role:Role { Name: {roleName}})")
				.WithParams(new
				{
					userId = user.Id,
					roleName = roleName
				})
				.CreateUnique("(user)-[:IN_ROLE]->(role:Role { Name: {roleName} })")
				.WithParam("roleName", roleName)
				.ExecuteWithoutResultsAsync();
		}

		/// <summary>
		/// Gets the roles for the user
		/// </summary>
		/// <param name="user">The user to get the roles for</param>
		/// <returns>A list of the roles the user is in.</returns>
		public async Task<IList<string>> GetRolesAsync(ApplicationUser user)
		{
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}

			string matchString = String.Format("(user:{0} {{ Id: {{userId}} }})-[:IN_ROLE]-(role:{1})", Configuration.Global.UserLabel, Configuration.Global.RoleLabel);

			var results = await DB.Cypher
									.Match(matchString)
									.WithParam("userId", user.Id)
									.Return(role => role.As<Role>())
									.ResultsAsync;
			
			return results.Select(role => role.Name).ToList();
		}

		/// <summary>
		/// Checks if the user is in the given role
		/// </summary>
		/// <param name="user">The user to check</param>
		/// <param name="roleName">The role</param>
		/// <returns>True, if in the role, otherwise false.</returns>
		public Task<bool> IsInRoleAsync(ApplicationUser user, string roleName)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Removes the user from the role.
		/// </summary>
		/// <param name="user">The user to remove from the role.</param>
		/// <param name="roleName">The role</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public Task RemoveFromRoleAsync(ApplicationUser user, string roleName)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Adds a claim to the user
		/// </summary>
		/// <param name="user">The user</param>
		/// <param name="claim">The claim</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public Task AddClaimAsync(ApplicationUser user, System.Security.Claims.Claim claim)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Gets the claims for the given user
		/// </summary>
		/// <param name="user">The user to get the claims for</param>
		/// <returns>The list of claims</returns>
		public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
		{
			List<Claim> claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.Email, user.Email));

			return Task.FromResult<IList<Claim>>(claims);
		}

		/// <summary>
		/// Removes the claim from the user
		/// </summary>
		/// <param name="user">The user from which to remove the claim</param>
		/// <param name="claim">The claim to remove</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public Task RemoveClaimAsync(ApplicationUser user, System.Security.Claims.Claim claim)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Whether the user has enabled two-factor authentication (2FA)
		/// </summary>
		/// <param name="user">The user to query</param>
		/// <returns>True, if 2FA is enabled, otherwise false.</returns>
		public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user)
		{
			return Task.FromResult<bool>(user.IsTwoFactorAuthEnabled);
		}

		/// <summary>
		/// Sets two factor authentication (2FA) for the user
		/// </summary>
		/// <param name="user">The user to set 2FA for</param>
		/// <param name="enabled">Whether to enable or disable 2FA</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public async Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled)
		{
			user.IsTwoFactorAuthEnabled = enabled;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// Adds an external login to a local user account
		/// </summary>
		/// <param name="user">The local user account</param>
		/// <param name="login">The external login</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public async Task AddLoginAsync(ApplicationUser user, UserLoginInfo login)
		{
			await DB.Cypher
					.Match("(user:User { Id: {userId} })")
					.WithParam("userId", user.Id)
					.CreateUnique("(user)-[:EXTERNAL_LOGIN]->(login:ExternalLogin {loginInfo})")
					.WithParam("loginInfo", login)
					.ExecuteWithoutResultsAsync();
		}

		/// <summary>
		/// Finds a user by external login.
		/// </summary>
		/// <param name="login">The external login details</param>
		/// <returns>The local user account, if found, otherwise null.</returns>
		public async Task<ApplicationUser> FindAsync(UserLoginInfo login)
		{
			if (login == null)
			{
				throw new ArgumentNullException("login");
			}

			string matchString = String.Format("(user:{0})-[]-(externalLogin:{1} {{ ProviderKey: {{loginProviderKey}} }})", Configuration.Global.UserLabel, Configuration.Global.ExternalLoginLabel);

			var query = DB.Cypher
								.Match(matchString)
								.WithParam("loginProviderKey", login.ProviderKey)
								.Return(user => user.As<ApplicationUser>());

			var result = (await query.ResultsAsync).SingleOrDefault();

			return result;
		}

		/// <summary>
		/// Gets external logins for the local user account
		/// </summary>
		/// <param name="user">The user to find external logins for.</param>
		/// <returns>A list of external logins for the given user.</returns>
		public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user)
		{
			if (user == null)
			{
				throw new ArgumentNullException("user");
			}

			string matchString = String.Format("(user:{0} {{ Id: {{userId}} }})-[:EXTERNAL_LOGIN]-(externalLogin:{1})", Configuration.Global.UserLabel, Configuration.Global.ExternalLoginLabel);

			var results = (await DB.Cypher
									.Match(matchString)
									.WithParam("userId", user.Id)
									.Return(externalLogin => externalLogin.As<UserLoginInfoPrivate>())
									.ResultsAsync)
									.Select(userLoginInfo => new UserLoginInfo(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey))
									.ToList();

			return results;
		}

		/// <summary>
		/// Removes an external login for the given local user account.
		/// </summary>
		/// <param name="user">The local user account</param>
		/// <param name="login">The external login to remove</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Gets the password hash for the given user.
		/// </summary>
		/// <param name="user">The local user account</param>
		/// <returns>The password hash.</returns>
		public Task<string> GetPasswordHashAsync(ApplicationUser user)
		{
			return Task.FromResult<string>(user.PasswordHash);
		}

		/// <summary>
		/// Whether the local user account has a password or not.
		/// </summary>
		/// <param name="user">The local user account</param>
		/// <returns>True, if the account has a password, otherwise false.</returns>
		public Task<bool> HasPasswordAsync(ApplicationUser user)
		{
			return Task.FromResult<bool>(user.PasswordHash != null);
		}

		/// <summary>
		/// Sets the password on the local user account.
		/// </summary>
		/// <param name="user">The user to set the password for</param>
		/// <param name="passwordHash">The password (hash) to set.</param>
		/// <returns>Nothing. Asynchronous void.</returns>
		public async Task SetPasswordHashAsync(ApplicationUser user, string passwordHash)
		{
			user.PasswordHash = passwordHash;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// Finds a user by their email address.
		/// </summary>
		/// <param name="email">The email address to look up</param>
		/// <returns>The user account, if found, otherwise null.</returns>
		public async Task<ApplicationUser> FindByEmailAsync(string email)
		{
			return await GetUserByEmailAddress(email);
		}

		/// <summary>
		/// Gets the email address for the given user.
		/// </summary>
		/// <param name="user">The local user account</param>
		/// <returns>The email address for the given user.</returns>
		public Task<string> GetEmailAsync(ApplicationUser user)
		{
			return Task.FromResult<string>(user.Email);
		}

		/// <summary>
		/// Gets whether the email address for the given user has been verified.
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public Task<bool> GetEmailConfirmedAsync(ApplicationUser user)
		{
			return Task.FromResult<bool>(user.IsEmailConfirmed);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="email"></param>
		/// <returns></returns>
		public async Task SetEmailAsync(ApplicationUser user, string email)
		{
			user.Email = email;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="confirmed"></param>
		/// <returns></returns>
		public async Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed)
		{
			user.IsEmailConfirmed = confirmed;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public Task<int> GetAccessFailedCountAsync(ApplicationUser user)
		{
			return Task.FromResult<int>(user.FailedLogins);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public Task<bool> GetLockoutEnabledAsync(ApplicationUser user)
		{
			return Task.FromResult<bool>(user.IsLockoutEnabled);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public Task<DateTimeOffset> GetLockoutEndDateAsync(ApplicationUser user)
		{
			return Task.FromResult<DateTimeOffset>(user.LockoutEndDate);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public async Task<int> IncrementAccessFailedCountAsync(ApplicationUser user)
		{
			user.FailedLogins += 1;

			await this.UpdateAsync(user);

			return user.FailedLogins;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public async Task ResetAccessFailedCountAsync(ApplicationUser user)
		{
			user.FailedLogins = 0;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="enabled"></param>
		/// <returns></returns>
		public async Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled)
		{
			user.IsLockoutEnabled = enabled;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="lockoutEnd"></param>
		/// <returns></returns>
		public async Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset lockoutEnd)
		{
			user.LockoutEndDate = lockoutEnd;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public Task<string> GetPhoneNumberAsync(ApplicationUser user)
		{
			return Task.FromResult<string>(Convert.ToString(user.PhoneNumber));
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user)
		{
			return Task.FromResult<bool>(user.IsPhoneNumberConfirmed);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="phoneNumber"></param>
		/// <returns></returns>
		public async Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber)
		{
			user.PhoneNumber = phoneNumber;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="user"></param>
		/// <param name="confirmed"></param>
		/// <returns></returns>
		public async Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed)
		{
			user.IsPhoneNumberConfirmed = confirmed;

			await this.UpdateAsync(user);
		}

		/// <summary>
		/// Disposes of resources
		/// </summary>
		/// <param name="includeManagedResources">Whether to dispose of managed resources as well as native resources</param>
		protected virtual void Dispose(bool includeManagedResources)
		{
		}

		// Necessary because UserLoginInfo is sealed but doesn't have a default ctor.
		// Summary:
		//     Represents a linked login for a user (i.e. a facebook/google account)
		private class UserLoginInfoPrivate
		{
			// Summary:
			//     Provider for the linked login, i.e. Facebook, Google, etc.
			public string LoginProvider { get; set; }
			//
			// Summary:
			//     User specific key for the login provider
			public string ProviderKey { get; set; }
		}
	}
}
