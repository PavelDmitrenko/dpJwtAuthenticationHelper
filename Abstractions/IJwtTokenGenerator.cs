using System;
using dpJwtAuthenticationHelper.Types;
using System.Collections.Generic;
using System.Security.Claims;

namespace dpJwtAuthenticationHelper.Abstractions
{

	public interface IJwtTokenGenerator
	{
		/// <summary>
		/// Generate a JSON Web Token with a ClaimsPrincipal object both containing the claims passed
		/// in. Use this method for ASP.NET Core application with cookie authentication.
		/// </summary>
		TokenWithClaimsPrincipal GenerateAccessTokenWithClaimsPrincipal(string userName,
			IEnumerable<Claim> userClaims, TimeSpan expiration);

		/// <summary>
		/// Generate a string JSON Web Token containing the claims passed in. Use this method for
		/// ASP.NET Core Web API applications with cookieless authentication.
		/// </summary>
		string GenerateAccessToken(string userName, IEnumerable<Claim> userClaims, TimeSpan expiration);
	}
}