using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Edgecastle.AspNet.Identity.Graph
{
	/// <summary>
	/// Represents a user in the system.
	/// </summary>
	public class User
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="User"/> class.
		/// </summary>
		public User()
		{
			// Safe by default
			IsLockoutEnabled = true;
		}

		/// <summary>
		/// The globally unique identifier for this user (Guid as string)
		/// </summary>
		public string Id { get; set; }

		/// <summary>
		/// The user's username
		/// </summary>
		public string UserName { get; set; }

		// Account milestones

		/// <summary>
		/// Date the user joined the service
		/// </summary>
		public DateTimeOffset Joined { get; set; }

		/// <summary>
		/// Date the user last logged in
		/// </summary>
		public DateTimeOffset LastLogin { get; set; }
	
		// Contact / verification details

		/// <summary>
		/// The user's phone number
		/// </summary>
		public string PhoneNumber { get; set; }

		/// <summary>
		/// Whether the phone number has been verified 
		/// </summary>
		public bool IsPhoneNumberConfirmed { get; set; }

		/// <summary>
		/// The user's email address
		/// </summary>
		public string Email { get; set; }

		/// <summary>
		/// Whether the email address has been verified
		/// </summary>
		public bool IsEmailConfirmed { get; set; }

		// Account Lockout

		/// <summary>
		/// Whether this account can be locked out
		/// </summary>
		public bool IsLockoutEnabled { get; set; }

		/// <summary>
		/// Number of failed logins
		/// </summary>
		public int FailedLogins { get; set; }

		/// <summary>
		/// Date the lockout expires
		/// </summary>
		public DateTimeOffset LockoutEndDate { get; set; }

		// Two-factor auth

		/// <summary>
		/// Whether this user has enabled two-factor authentication (2FA)
		/// </summary>
		public bool IsTwoFactorAuthEnabled { get; set; }

	}
}
