using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Graph
{
	/// <summary>
	/// Allows configuration of the labels used for different objects in the graph DB
	/// </summary>
	public class Configuration
	{
		private static Configuration _singleton = null;

		private NameValueCollection Settings = null;

		/// <summary>
		/// Initializes a new instance of the <see cref="Configuration"/> class.
		/// </summary>
		/// <param name="settings">The settings used to define the labels</param>
		public Configuration(NameValueCollection settings)
		{
			this.Settings = settings ?? ConfigurationManager.AppSettings;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="Configuration"/> class.
		/// </summary>
		public Configuration() : this(null) { }

		/// <summary>
		/// The label applied to User objects (nodes) in the graph database
		/// </summary>
		public string UserLabel
		{
			get
			{
				return Settings["UserLabel"] ?? "User";
			}
		}

		/// <summary>
		/// The label applied to External Login objects (nodes) in the graph database
		/// </summary>
		public string ExternalLoginLabel
		{
			get
			{
				return Settings["ExternalLoginLabel"] ?? "ExternalLogin";
			}
		}

		/// <summary>
		/// The label applied to Role objects (nodes) in the graph database
		/// </summary>
		public string RoleLabel
		{
			get
			{
				return Settings["RoleLabel"] ?? "Role";
			}
		}

		/// <summary>
		/// Global singleton for accessing common graph configuration settings
		/// </summary>
		public static Configuration Global
		{
			get
			{
				if (_singleton == null)
				{
					_singleton = new Configuration();
				}

				return _singleton;
			}
		}
	}
}
