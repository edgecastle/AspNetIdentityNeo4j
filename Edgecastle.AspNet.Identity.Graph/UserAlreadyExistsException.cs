using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Edgecastle.AspNet.Identity.Graph
{
	/// <summary>
	/// Error thrown when user already exists
	/// </summary>
	[Serializable]
	public class UserAlreadyExistsException : Exception
	{
	}
}
