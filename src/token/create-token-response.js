const {
  InvalidArgumentError,
} = require('../utils/errors');

module.exports = ({
  accessToken,
  accessTokenLifetime,
  refreshToken,
  scope,
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

  if (scope) {
    response.scope = scope;
  }

  if (customAttributes) {
    return {
      ...response,
      ...customAttributes,
    }
  }

  return response;
}