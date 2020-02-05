const {
  InvalidArgumentError,
  InvalidGrantError
} = require('../errors');

const createBaseGrantTypeHelpers = require('./base-grant-type');

const clientCredentialGrantType = (options = {}) => {
  const {
    generateAccessToken,
    getAccessTokenExpiresAt,
    getScope,
    validateScope
  } = createBaseGrantTypeHelpers(options);

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getUserFromClient) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getUserFromClient()`');
  }

  if (!options.model.saveToken) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
  }

  const getUserFromClient = async (client) => {
    const user = await options.model.getUserFromClient(client);

    if (!user) {
      throw new InvalidGrantError('Invalid grant: user credentials are invalid');
    }

    return user;
  }

  const saveToken = async (user, client, scope) => {
    const validatedScope = validateScope(user, client, scope);
    const accessToken = await generateAccessToken(client, user, scope);
    const accessTokenExpiresAt = getAccessTokenExpiresAt(client, user, scope);

    const token = {
      accessToken,
      accessTokenExpiresAt,
      scope: validatedScope
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

    const user = await getUserFromClient(client);

    return saveToken(user, client, scope);
  }

  return {
    getUserFromClient,
    saveToken,
    handle,
  };
};

module.exports = clientCredentialGrantType;