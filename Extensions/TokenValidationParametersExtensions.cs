using dpJwtAuthenticationHelper.Types;
using Microsoft.IdentityModel.Tokens;

namespace dpJwtAuthenticationHelper.Extensions
{
    public static class TokenValidationParametersExtensions
    {
        public static TokenOptions ToTokenOptions(this TokenValidationParameters tokenValidationParameters,
            int tokenExpiryInMinutes = 5)
        {
            return new TokenOptions(tokenValidationParameters.ValidIssuer,
                tokenValidationParameters.ValidAudience,
                tokenValidationParameters.IssuerSigningKey,
                tokenExpiryInMinutes);
        }
    }
}