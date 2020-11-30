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

  const getRefreshToken = async (eventRequest, client, options) => {
    if (!eventRequest.body.refresh_token) {
      throw new InvalidRequestError('Missing parameter: `refresh_token`');
    }
  
    if (!is.vschar(eventRequest.body.refresh_token)) {
      throw new InvalidRequestError('Invalid parameter: `refresh_token`');
    }

    const refreshToken = await options.model.getRefreshToken(eventRequest.body.refresh_token);

    if (!refreshToken) {
      throw new InvalidGrantError('Invalid grant: refresh token is invalid');
    }

    if (!refreshToken.client) {
      throw new ServerError('Server error: `getRefreshToken()` did not return a `client` object');
    }

    if (!refreshToken.user) {
      throw new ServerError('Server error: `getRefreshToken()` did not return a `user` object');
    }

    if (refreshToken.client.id !== client.id) {
      throw new InvalidGrantError('Invalid grant: refresh token is invalid');
    }

    if (refreshToken.refreshTokenExpiresAt && !(refreshToken.refreshTokenExpiresAt instanceof Date)) {
      throw new ServerError('Server error: `refreshTokenExpiresAt` must be a Date instance');
    }

    if (refreshToken.refreshTokenExpiresAt && refreshToken.refreshTokenExpiresAt < new Date()) {
      throw new InvalidGrantError('Invalid grant: refresh token has expired');
    }

    return refreshToken;
  }
  
  /**
   * Revoke the refresh token.
   *
   * @see https://tools.ietf.org/html/rfc6749#section-6
   */
  const revokeToken = async (token, options) => {
    if (options.alwaysIssueNewRefreshToken === false) {
      return token;
    }

    const isValid = await options.model.revokeToken(token.refreshToken);

    if (!isValid) {
      throw new InvalidGrantError('Invalid grant: refresh token is invalid');
    }

    return token;
  }

  const saveToken = async (user, client, scope, options) => {
    // TODO: Support scope
    // const scope = await validateScope(user, client, scope);
    const accessToken = await generateAccessToken(client, user);
    const accessTokenExpiresAt = getAccessTokenExpiresAt();
    const refreshToken = await generateRefreshToken(client, user);
    const refreshTokenExpiresAt = getRefreshTokenExpiresAt();

    const token = {
      accessToken,
      accessTokenExpiresAt,
      refreshToken,
      refreshTokenExpiresAt,
      scope: null,
    }
   
    if (options.alwaysIssueNewRefreshToken !== false) {
      token.refreshToken = refreshToken;
      token.refreshTokenExpiresAt = refreshTokenExpiresAt;
    }

    return options.model.saveToken(token, client, user);
  }

  const handle = async (eventRequest, client, options) => {
    if (!eventRequest) {
      throw new InvalidArgumentError('Missing parameter: `eventRequest`');
    }

    if (!client) {
      throw new InvalidArgumentError('Missing parameter: `client`');
    }

    if (!options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }

    const refreshToken = await getRefreshToken(eventRequest, client, options);

    const token = await revokeToken(refreshToken, options);

    return saveToken(token.user, client, token.scope, options);
  }

  return {
    getRefreshToken,
    revokeToken,
    saveToken,
    handle,
  };
};

module.exports = refreshTokenGrantType;
