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

  /**
  * Get user using a username/password combination.
  */
  const getUser = async () => {
    if (!request.body.username) {
      throw new InvalidRequestError('Missing parameter: `username`');
    }
  
    if (!request.body.password) {
      throw new InvalidRequestError('Missing parameter: `password`');
    }
  
    if (!is.uchar(request.body.username)) {
      throw new InvalidRequestError('Invalid parameter: `username`');
    }
  
    if (!is.uchar(request.body.password)) {
      throw new InvalidRequestError('Invalid parameter: `password`');
    }
  
    return promisify(this.model.getUser, 2).call(this.model, request.body.username, request.body.password)
      .then(function(user) {
        if (!user) {
          throw new InvalidGrantError('Invalid grant: user credentials are invalid');
        }
  
        return user;
      });
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

    const scope = options.model.getScope(eventRequest);

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
