const {
  InvalidArgumentError,
  InvalidGrantError
} = require('../errors');

const createBaseGrantTypeHelpers = require('./base-grant-type');

const clientCredentialGrantType = (options = {}) => {
  const {
    generateAccessToken,
    getAccessTokenExpiresAt,
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

  const saveToken = async (user, client) => {
    // TODO: Support scope
    // const scope = await validateScope(user, client, scope);
    const accessToken = await generateAccessToken(client, user);
    const accessTokenExpiresAt = getAccessTokenExpiresAt(client, user);

    const token = {
      accessToken,
      accessTokenExpiresAt,
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

    const user = await getUserFromClient(client);

    return saveToken(user, client);
  }

  return {
    getUserFromClient,
    saveToken,
    handle,
  };
};

module.exports = clientCredentialGrantType;