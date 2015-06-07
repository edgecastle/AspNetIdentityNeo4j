using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Neo4j
{
	/// <summary>
	/// An ASP.NET identity (user)
	/// </summary>
    public class ApplicationUser : User, IUser<string>
	{
        /// <summary>
        /// Initializes a new instance of the <see cref="ApplicationUser"/> class
        /// </summary>
        public ApplicationUser() { }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }

        /// <summary>
        /// The user's password hash
        /// </summary>
        public string PasswordHash { get; set; }

		/// <summary>
		/// Cleans and sets up a new <see cref="ApplicationUser"/> object for persistence to the graph database
		/// </summary>
		public void SanitizeNewUser()
		{
			this.UserName = this.UserName.ToLowerInvariant();
			this.Email = this.Email.ToLowerInvariant();
			this.Id = Guid.NewGuid().ToString();
			this.Joined = DateTimeOffset.UtcNow;
			this.LastLogin = this.Joined;
		}
    }
}
