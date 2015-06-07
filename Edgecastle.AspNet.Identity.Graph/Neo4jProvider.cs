using Neo4jClient;
using Neo4jClient.Cypher;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Neo4j
{
	/// <summary>
	/// Provides functionality to interact with a Neo4j graph database
	/// </summary>
	public static class Neo4jProvider
	{
		/// <summary>
		/// Gets a new instance of the Neo4jClient <see cref="GraphClient"/>
		/// </summary>
		/// <returns></returns>
		public static GraphClient GetClient()
		{
			string connectionString = Configuration.Global.ConnectionString;
			Uri uri;
			if(!Uri.TryCreate(connectionString, UriKind.Absolute, out uri))
			{
				throw new ApplicationException("No connection string provided for Neo4j instance. Please set the 'Neo4jConnectionString' appsetting.");
			}

			GraphClient client = new GraphClient(uri);
			client.Connect();

			return client;
		}
	}
}
