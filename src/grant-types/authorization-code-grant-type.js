const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidGrantError
} = require('../errors');

const is = require('../validator/is');

const createBaseGrantTypeHelpers = require('./base-grant-type');

const authorizationCodeGrantType = (options = {}) => {
  const {
    generateAccessToken,
    getAccessTokenExpiresAt,
    generateRefreshToken,
    getRefreshTokenExpiresAt,
  } = createBaseGrantTypeHelpers(options);

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getAuthorizationCode()`');
  }

  if (!options.model.revokeAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `revokeAuthorizationCode()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  /**
  * Get the stored authorization code
  */
  const getAuthorizationCode = async (eventRequest, client) => {
    if (!eventRequest.body.code) {
      throw new InvalidRequestError('Missing parameter: `code`');
    }
  
    if (!is.vschar(eventRequest.body.code)) {
      throw new InvalidRequestError('Invalid parameter: `code`');
    }

    const code = await options.model.getAuthorizationCode(eventRequest.body.code);

    if (!code) {
      throw new InvalidGrantError('Invalid grant: authorization code is invalid');
    }

    if (!code.client) {
      throw new ServerError('Server error: `getAuthorizationCode()` did not return a `client` object');
    }

    if (!code.user) {
      throw new ServerError('Server error: `getAuthorizationCode()` did not return a `user` object');
    }

    if (code.client.id !== client.id) {
      throw new InvalidGrantError('Invalid grant: authorization code is invalid');
    }

    if (!(code.expiresAt instanceof Date)) {
      throw new ServerError('Server error: `expiresAt` must be a Date instance');
    }

    if (code.expiresAt < new Date()) {
      throw new InvalidGrantError('Invalid grant: authorization code has expired');
    }

    if (code.redirectUri && !is.uri(code.redirectUri)) {
      throw new InvalidGrantError('Invalid grant: `redirect_uri` is not a valid URI');
    }

    return code;
  };

  /**
   * Validates the redirect_uri
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
   */
  const validateRedirectUri = async (eventRequest, code) => {
    if (!code.redirectUri) {
      return;
    }
 
    const redirectUri = eventRequest.body.redirect_uri || eventRequest.query.redirect_uri;
 
    if (!is.uri(redirectUri)) {
      throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
    }
 
    if (redirectUri !== code.redirectUri) {
      throw new InvalidRequestError('Invalid request: `redirect_uri` is invalid');
    }
  };

  /**
   * Revoke the authorization code
   *
   * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
   */
  const revokeAuthorizationCode = async (code) => {
    const status = await options.model.revokeAuthorizationCode(code);

    if (!status) {
      throw new InvalidGrantError('Invalid grant: authorization code is invalid');
    }

    return code;
  };

  const saveToken = async (user, client, authorizationCode) => {
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

    const code = await getAuthorizationCode(eventRequest, client);

    validateRedirectUri(eventRequest, code);

    revokeAuthorizationCode(code);

    return saveToken(user, client, code.authorizationCode, code.scope);
  }

  return {
    getAuthorizationCode,
    validateRedirectUri,
    revokeAuthorizationCode,
    saveToken,
    handle,
  };
};

module.exports = authorizationCodeGrantType;
