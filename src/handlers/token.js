const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidClientError,
  ServerError,
} = require('../utils/errors');

const parseAWSEvent = require('../utils/parse-aws-event');
const is = require('../utils/request-validator');

const {
  validateTokenModel,
  createTokenResponse
} = require('../token');

const grantTypes = {
  client_credentials: require('../grant-types/client-credentials'),
};

const getClientCredentials = (body) => {
  const grantType = body.grant_type;

  if (body.client_id && body.client_secret) {
    return { clientId: body.client_id, clientSecret: body.client_secret };
  }

  // TODO
  // if (!isClientAuthenticationRequired(grantType)) {
  //   if (body.client_id) {
  //     return { clientId: body.client_id };
  //   }
  // }

  throw new InvalidClientError('Cannot read client credentials from body');
}

const getClient = async ({ body }, options) => {
  try {
    const credentials = getClientCredentials(body);
    const grantType = body.grant_type;

    if (!credentials.clientId) {
      throw new InvalidRequestError('Missing parameter: `client_id`');
    }

    // TODO
    // if (isClientAuthenticationRequired(grantType) && !credentials.clientSecret) {
    //   throw new InvalidRequestError('Missing parameter: `client_secret`');
    // }

    // if (!is.vschar(credentials.clientId)) {
    //   throw new InvalidRequestError('Invalid parameter: `client_id`');
    // }

    // if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
    //   throw new InvalidRequestError('Invalid parameter: `client_secret`');
    // }

    return options.model.getClient(credentials.clientId, credentials.clientSecret);
  } catch (error) {
    // TODO
    // Include the "WWW-Authenticate" response header field if the client
    // attempted to authenticate via the "Authorization" request header.
    //
    // @see https://tools.ietf.org/html/rfc6749#section-5.2.
    // if ((error instanceof InvalidClientError) && request.get('authorization')) {
    //   response.set('WWW-Authenticate', 'Basic realm="Service"');

    //   throw new InvalidClientError(e, { code: 401 });
    // }

    // throw e;
  }
}

const getAccessTokenLifetime = (client, options) => {
  return client.accessTokenLifetime || options.accessTokenLifetime;
};

const getRefreshTokenLifetime = (client, options) => {
  return client.refreshTokenLifetime || options.refreshTokenLifetime;
}

const handleGrantType = (eventRequest, client, options) => {
  // const grantType = eventRequest.body.grant_type;

  // if (!grantType) {
  //   throw new InvalidRequestError('Missing parameter: `grant_type`');
  // }

  // TODO
  // if (!is.nchar(grantType) && !is.uri(grantType)) {
  //   throw new InvalidRequestError('Invalid parameter: `grant_type`');
  // }

  // if (!_.has(this.grantTypes, grantType)) {
  //   throw new UnsupportedGrantTypeError('Unsupported grant type: `grant_type` is invalid');
  // }

  // if (!_.includes(client.grants, grantType)) {
  //   throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
  // }

  const accessTokenLifetime = getAccessTokenLifetime(client, options);
  const refreshTokenLifetime = getRefreshTokenLifetime(client, options);

  const createGrantType = grantTypes['client_credentials'];

  const tokenOptions = {
    accessTokenLifetime: accessTokenLifetime,
    model: options.model,
    refreshTokenLifetime: refreshTokenLifetime,
    alwaysIssueNewRefreshToken: options.alwaysIssueNewRefreshToken
  };

  const {
    handle
  } = createGrantType(tokenOptions);

  return handle(eventRequest, client);
}

module.exports = async (event, config) => {
  try {
    const options = Object.assign({
      accessTokenLifetime: 60 * 60,             // 1 hour
      refreshTokenLifetime: 60 * 60 * 24 * 14,  // 2 weeks
      allowExtendedTokenAttributes: false,
      requireClientAuthentication: {},          // Defaults to true for all grant types
      ...config,
    });

    if (!options.accessTokenLifetime) {
      throw new InvalidArgumentError('Missing option: `accessTokenLifetime`');
    }

    if (!options.refreshTokenLifetime) {
      throw new InvalidArgumentError('Missing option: `refreshTokenLifetime`');
    }

    if (!options.model.getClient) {
      throw new InvalidArgumentError('model does not implement `getClient()`');
    }

    // TODO - Extra option configurations
    // this.accessTokenLifetime = options.accessTokenLifetime;
    // this.grantTypes = _.assign({}, grantTypes, options.extendedGrantTypes);
    // this.model = options.model;
    // this.refreshTokenLifetime = options.refreshTokenLifetime;
    // this.allowExtendedTokenAttributes = options.allowExtendedTokenAttributes;
    // this.requireClientAuthentication = options.requireClientAuthentication || {};
    // this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken !== false;

    // Parse event request
    const eventRequest = parseAWSEvent(event);

    const client = await getClient(eventRequest, options);

    if (!client) {
      throw new InvalidClientError('client is invalid');
    }

    if (!client.grants) {
      throw new ServerError('missing client `grants`');
    }

    if (!(client.grants instanceof Array)) {
      throw new ServerError('`grants` must be an array');
    }

    const data = await handleGrantType(eventRequest, client, options);

    const token = validateTokenModel(data, {
      allowExtendedTokenAttributes: options.allowExtendedTokenAttributes
    });

    const tokenResponse = createTokenResponse(token);

    return tokenResponse;
  } catch (error) {
    throw new ServerError(error);
  }
}