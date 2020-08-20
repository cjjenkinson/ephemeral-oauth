const {
  InvalidArgumentError,
  InvalidScopeError,
} = require('../errors');

const is = require('../validator/is');

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
    alwaysIssueNewRefreshToken: options.alwaysIssueNewRefreshToken,
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

  const getScope = (eventRequest) => {
    if (!is.nqschar(eventRequest.body.scope)) {
      throw new InvalidArgumentError('Invalid parameter: `scope`');
    }
  
    return eventRequest.body.scope;
  }

  const validateScope = async (user, client, scope) => {
    if (options.model.validateScope) {
      const scope = await options.model.validateScope(user, client, scope);

      if (!scope) {
        throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
      }

      return scope;
    } else {
      return scope;
    }
  }

  return {
    generateAccessToken,
    generateRefreshToken,
    getAccessTokenExpiresAt,
    getRefreshTokenExpiresAt,
    getScope,
    validateScope,
  }
}

module.exports = createBaseGrantTypeHelpers