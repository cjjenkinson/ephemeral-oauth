const {
  InvalidArgumentError,
} = require('../errors');

module.exports = ({
  accessToken,
  accessTokenLifetime,
  refreshToken,
  customAttributes = {},
}) => {
  if (!accessToken) {
    throw new InvalidArgumentError('Missing parameter: `accessToken`');
  }

  const response = {
    access_token: accessToken,
    token_type: 'Bearer'
  };

  if (accessTokenLifetime) {
    response.expires_in = accessTokenLifetime;
  }

  if (refreshToken) {
    response.refresh_token = refreshToken;
  }

  if (customAttributes) {
    return {
      ...response,
      ...customAttributes,
    }
  }

  return response;
}