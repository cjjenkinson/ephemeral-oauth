const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidGrantError
} = require('../errors');

const is = require('../validator/is');

const createBaseGrantTypeHelpers = require('./base-grant-type');

const passwordGrantType = (options = {}) => {
  const {
    generateAccessToken,
    getAccessTokenExpiresAt,
    generateRefreshToken,
    getRefreshTokenExpiresAt,
    getScope,
  } = createBaseGrantTypeHelpers(options);

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUser) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getUser()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  /**
  * Get user using a username/password combination.
  */
  const getUser = async (eventRequest) => {
    if (!eventRequest.body.username) {
      throw new InvalidRequestError('Missing parameter: `username`');
    }
  
    if (!eventRequest.body.password) {
      throw new InvalidRequestError('Missing parameter: `password`');
    }
  
    const user = await options.model.getUser(eventRequest.body.username, eventRequest.body.password);

    if (!user) {
      throw new InvalidGrantError('Invalid grant: user credentials are invalid');
    }

    return user;
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

    const scope = getScope(eventRequest);

    const user = await getUser(eventRequest);

    return saveToken(user, client, scope);
  }

  return {
    getUser,
    saveToken,
    handle,
  };
};

module.exports = passwordGrantType;
