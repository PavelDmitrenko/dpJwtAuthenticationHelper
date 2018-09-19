using dpJwtAuthenticationHelper.Types;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace dpJwtAuthenticationHelper
{

	/// <summary>
	/// An implementation of <see cref="ISecureDataFormat{TData}"/> to securely store a Json Web
	/// Token (JWT) in a cookie i.e. <see cref="AuthenticationTicket"/>
	/// </summary>
	public sealed class JwtAuthTicketFormat : ISecureDataFormat<AuthenticationTicket>
	{
		private const string Algorithm = SecurityAlgorithms.HmacSha256;
		private readonly TokenValidationParameters validationParameters;
		private readonly IDataSerializer<AuthenticationTicket> ticketSerializer;
		private readonly IDataProtector dataProtector;

		public JwtAuthTicketFormat(TokenValidationParameters validationParameters,
			IDataSerializer<AuthenticationTicket> ticketSerializer,
			IDataProtector dataProtector)
		{
			this.validationParameters = validationParameters ?? throw new ArgumentNullException($"{nameof(validationParameters)} cannot be null");
			this.ticketSerializer = ticketSerializer ?? throw new ArgumentNullException($"{nameof(ticketSerializer)} cannot be null");
			this.dataProtector = dataProtector ?? throw new ArgumentNullException($"{nameof(dataProtector)} cannot be null");
		}

		/// <summary>
		/// Does the exact opposite of the Protect methods i.e. converts an encrypted string back to
		/// the original <see cref="AuthenticationTicket"/> instance containing the JWT and claims.
		/// </summary>
		/// <param name="protectedText"></param>
		/// <returns></returns>
		public AuthenticationTicket Unprotect(string protectedText) => Unprotect(protectedText, null);
		public string Protect(AuthenticationTicket data) => Protect(data, null);

		public AuthenticationTicket Unprotect(string protectedText, string purpose)
		{
			var authTicket = ticketSerializer.Deserialize(
				dataProtector.Unprotect(
					Base64UrlTextEncoder.Decode(protectedText)));

			var embeddedJwt = authTicket
				.Properties?
				.GetTokenValue(TokenConstants.TokenName);

			try
			{
				new JwtSecurityTokenHandler()
					.ValidateToken(embeddedJwt, validationParameters, out var token);

				if (!(token is JwtSecurityToken jwt))
				{
					throw new SecurityTokenValidationException("JWT token was found to be invalid");
				}

				if (!jwt.Header.Alg.Equals(Algorithm, StringComparison.Ordinal))
				{
					throw new ArgumentException($"Algorithm must be '{Algorithm}'");
				}
			}
			catch (SecurityTokenExpiredException)
			{
				return null;
			}
			catch (Exception)
			{
				return null;
			}

			return authTicket;
		}

	
		/// <summary>
		/// Protect the authentication ticket and convert it to an encrypted string before sending
		/// out to the users. Additionally, specify the purpose of encryption, default is null.
		/// </summary>
		/// <param name="data">an instance of <see cref="AuthenticationTicket"/></param>
		/// <param name="purpose">a purpose string</param>
		/// <returns>encrypted string representing the <see cref="AuthenticationTicket"/></returns>
		public string Protect(AuthenticationTicket data, string purpose)
		{
			var array = ticketSerializer.Serialize(data);

			return Base64UrlTextEncoder.Encode(dataProtector.Protect(array));
		}
	}
}