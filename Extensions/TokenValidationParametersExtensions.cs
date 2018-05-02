using System;
using dpJwtAuthenticationHelper.Types;
using Microsoft.IdentityModel.Tokens;

namespace dpJwtAuthenticationHelper.Extensions
{
    public static class TokenValidationParametersExtensions
    {
        public static TokenOptions ToTokenOptions(this TokenValidationParameters tokenValidationParameters,
            TimeSpan tokenExpiry)
        {
            return new TokenOptions(tokenValidationParameters.ValidIssuer,
                tokenValidationParameters.ValidAudience,
                tokenValidationParameters.IssuerSigningKey,
	            tokenExpiry
			  );
        }
    }
}