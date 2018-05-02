using Microsoft.IdentityModel.Tokens;
using System;

namespace dpJwtAuthenticationHelper.Types
{
	/// <summary>
	/// A structure containting the various options required to generate a valid Json Web Token
	/// </summary>
	public sealed class TokenOptions
	{

		/// <summary>
		/// Creates a new instance of <see cref="TokenOptions"/>
		/// </summary>

		public SecurityKey SigningKey { get; }

		public string Issuer { get; }

		public string Audience { get; }

		public TimeSpan TokenExpiry { get; }

		public TokenOptions(string issuer,
							string audience,
							SecurityKey signingKey,
							TimeSpan tokenExpiry)
		{
			if (string.IsNullOrWhiteSpace(audience))
			{
				throw new ArgumentNullException($"{nameof(Audience)} is mandatory in order to generate a JWT!");
			}

			if (string.IsNullOrWhiteSpace(issuer))
			{
				throw new ArgumentNullException($"{nameof(Issuer)} is mandatory in order to generate a JWT!");
			}

			Audience = audience;
			Issuer = issuer;
			SigningKey = signingKey ?? throw new ArgumentNullException($"{nameof(SigningKey)} is mandatory in order to generate a JWT!");

			TokenExpiry = tokenExpiry;
		}
	}

	public struct TokenConstants
	{
		public const string TokenName = "jwt";
	}
}