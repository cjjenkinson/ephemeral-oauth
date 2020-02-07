const {
  InvalidArgumentError,
} = require('../errors');

const {
  generateRandomToken
} = require('../utils/generate-token');

const createBaseGrantTypeHelpers = (options = {}) => {
  if (!options.accessTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  const baseGrantOptions = {
    accessTokenLifetime: options.accessTokenLifetime,
    model: options.model,
    refreshTokenLifetime: options.refreshTokenLifetime,
    alwaysIssueNewRefreshToken:options.alwaysIssueNewRefreshToken,
  }

  const generateAccessToken = async (client, user, scope) => {
    if (baseGrantOptions.model.generateAccessToken) {
      const accessToken = await baseGrantOptions.model.generateAccessToken(client, user, scope);

      return accessToken;
    }

    return generateRandomToken();
  }

  const generateRefreshToken = async (client, user, scope) => {
    if (baseGrantOptions.model.generateRefreshToken) {
      const accessToken = await baseGrantOptions.model.generateRefreshToken(client, user, scope);

      return accessToken;
    }

    return generateRandomToken();
  }

  const getAccessTokenExpiresAt = () => {
    const expires = new Date();

    expires.setSeconds(expires.getSeconds() + baseGrantOptions.accessTokenLifetime);

    return expires;
  }

  const getRefreshTokenExpiresAt = () => {
    const expires = new Date();

    expires.setSeconds(expires.getSeconds() + baseGrantOptions.refreshTokenLifetime);

    return expires;
  }

  return {
    generateAccessToken,
    generateRefreshToken,
    getAccessTokenExpiresAt,
    getRefreshTokenExpiresAt,
  }
}

module.exports = createBaseGrantTypeHelpers