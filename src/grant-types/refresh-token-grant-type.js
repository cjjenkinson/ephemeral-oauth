const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidGrantError
} = require('../errors');

const is = require('../validator/is');

const createBaseGrantTypeHelpers = require('./base-grant-type');

const refreshTokenGrantType = (options = {}) => {
  const {
    generateAccessToken,
    getAccessTokenExpiresAt,
    generateRefreshToken,
    getRefreshTokenExpiresAt,
  } = createBaseGrantTypeHelpers(options);

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUser) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getAuthorizationCode()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  const getRefreshToken = async (eventRequest, client) => {
    // if (!request.body.refresh_token) {
    //   throw new InvalidRequestError('Missing parameter: `refresh_token`');
    // }
  
    // if (!is.vschar(request.body.refresh_token)) {
    //   throw new InvalidRequestError('Invalid parameter: `refresh_token`');
    // }
  
    // return promisify(this.model.getRefreshToken, 1).call(this.model, request.body.refresh_token)
    //   .then(function(token) {
    //     if (!token) {
    //       throw new InvalidGrantError('Invalid grant: refresh token is invalid');
    //     }
  
    //     if (!token.client) {
    //       throw new ServerError('Server error: `getRefreshToken()` did not return a `client` object');
    //     }
  
    //     if (!token.user) {
    //       throw new ServerError('Server error: `getRefreshToken()` did not return a `user` object');
    //     }
  
    //     if (token.client.id !== client.id) {
    //       throw new InvalidGrantError('Invalid grant: refresh token is invalid');
    //     }
  
    //     if (token.refreshTokenExpiresAt && !(token.refreshTokenExpiresAt instanceof Date)) {
    //       throw new ServerError('Server error: `refreshTokenExpiresAt` must be a Date instance');
    //     }
  
    //     if (token.refreshTokenExpiresAt && token.refreshTokenExpiresAt < new Date()) {
    //       throw new InvalidGrantError('Invalid grant: refresh token has expired');
    //     }
  
    //     return token;
    //   });
  }
  
  /**
   * Revoke the refresh token.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-6
   */
  const revokeToken = async (token) => {
    // if (this.alwaysIssueNewRefreshToken === false) {
    //   return Promise.resolve(token);
    // }
  
    // return promisify(this.model.revokeToken, 1).call(this.model, token)
    //   .then(function(status) {
    //     if (!status) {
    //       throw new InvalidGrantError('Invalid grant: refresh token is invalid');
    //     }
  
    //     return token;
    //   });
  }

  const saveToken = async (user, client, scope) => {
    // TODO: Support scope
    // const scope = await validateScope(user, client, scope);
    const accessToken = await generateAccessToken(client, user);
    const accessTokenExpiresAt = getAccessTokenExpiresAt();
    const refreshToken = await generateRefreshToken(client, user);
    const refreshTokenExpiresAt = getRefreshTokenExpiresAt();

    const token = {
      accessToken,
      authorizationCode,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
      scope: null,
    }

    return options.model.saveToken(token, client, user);
  }

  const handle = async (eventRequest, client) => {
    if (!eventRequest) {
      throw new InvalidArgumentError('Missing parameter: `eventRequest`');
    }

    if (!client) {
      throw new InvalidArgumentError('Missing parameter: `client`');
    }

    const refreshToken = await getRefreshToken(eventRequest, client);

    const token = await revokeToken(token);

    return saveToken(token.user, client, token.scope);
  }

  return {
    getRefreshToken,
    revokeToken,
    saveToken,
    handle,
  };
};

module.exports = refreshTokenGrantType;
