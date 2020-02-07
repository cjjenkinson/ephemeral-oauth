const { has, includes, assign } = require('lodash');

const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidClientError,
  UnsupportedGrantTypeError,
  UnauthorizedClientError,
  LambdaError,
  OAuthError,
} = require('../errors');

const parseAWSEvent = require('../utils/parse-aws-event');
const is = require('../utils/request-validator');

const {
  validateTokenModel,
  createTokenResponse
} = require('../token');

const grantTypes = {
  client_credentials: require('../grant-types/client-credentials'),
};

const isClientAuthenticationRequired = (grantType, options) => {
  if (Object.keys(options.requireClientAuthentication).length > 0) {
    return (typeof options.requireClientAuthentication[grantType] !== 'undefined') ? options.requireClientAuthentication[grantType] : true;
  }

  return true;
}

/**
 * Get client credentials.
 *
 * The client credentials may be sent using the HTTP Basic authentication scheme or, alternatively,
 * the `client_id` and `client_secret` can be passed in the body.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
 */

const getClientCredentials = (body, options) => {
  const grantType = body.grant_type;

  if (body.client_id && body.client_secret) {
    return { clientId: body.client_id, clientSecret: body.client_secret };
  }

  if (!isClientAuthenticationRequired(grantType, options)) {
    if (body.client_id) {
      return { clientId: body.client_id };
    }
  }

  throw new InvalidClientError('Cannot read client credentials from body');
}

const getClient = async ({ headers, body }, options) => {
  try {
    const isValidContentType = (headers['Content-Type'] === 'application/x-www-form-urlencoded');

    if (!isValidContentType) {
      throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded');
    }

    const credentials = getClientCredentials(body, options);
    const grantType = body.grant_type;

    if (!credentials.clientId) {
      throw new InvalidRequestError('Missing parameter: `client_id`');
    }

    if (isClientAuthenticationRequired(grantType, options) && !credentials.clientSecret) {
      throw new InvalidRequestError('Missing parameter: `client_secret`');
    }

    if (!is.vschar(credentials.clientId)) {
      throw new InvalidRequestError('Invalid parameter: `client_id`');
    }

    if (credentials.clientSecret && !is.vschar(credentials.clientSecret)) {
      throw new InvalidRequestError('Invalid parameter: `client_secret`');
    }

    return options.model.getClient(credentials.clientId, credentials.clientSecret);
  } catch (error) {
    // TODO
    // Include the "WWW-Authenticate" response header field if the client
    // attempted to authenticate via the "Authorization" request header.
    //
    // @see https://tools.ietf.org/html/rfc6749#section-5.2.
    // if ((error instanceof InvalidClientError) && request.get('authorization')) {
    //   return {
    //      headers: { 'WWW-Authenticate', 'Bearer realm="Service" }
    //    }
    //   throw new InvalidClientError(error, { code: 401 });
    // }

    throw new LambdaError(error);
  }
}

const getAccessTokenLifetime = (client, options) => {
  return client.accessTokenLifetime || options.accessTokenLifetime;
};

const getRefreshTokenLifetime = (client, options) => {
  return client.refreshTokenLifetime || options.refreshTokenLifetime;
}

const handleGrantType = (eventRequest, client, options) => {
  const grantType = eventRequest.body.grant_type;

  if (!grantType) {
    throw new InvalidRequestError('Missing parameter: `grant_type`');
  }

  if (!is.nchar(grantType) && !is.uri(grantType)) {
    throw new InvalidRequestError('Invalid parameter: `grant_type`');
  }

  if (!has(grantTypes, grantType)) {
    throw new UnsupportedGrantTypeError('Unsupported grant type: `grant_type` is invalid');
  }

  if (!includes(client.grants, grantType)) {
    throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
  }

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
      allowExtendedTokenAttributes: config.allowExtendedTokenAttributes || false,
      requireClientAuthentication: config.requireClientAuthentication || {},
      alwaysIssueNewRefreshToken: config.alwaysIssueNewRefreshToken || false,
      grantTypes: assign({}, grantTypes, config.extendedGrantTypes),
      // Defaults to true for all grant types
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

    // Parse event request - AWS Lambda specific but can open up to more cloud function providers
    const eventRequest = parseAWSEvent(event);

    const client = await getClient(eventRequest, options);

    if (!client) {
      throw new InvalidClientError('client is invalid');
    }

    if (!client.grants) {
      throw new LambdaError('missing client `grants`');
    }

    if (!(client.grants instanceof Array)) {
      throw new LambdaError('`grants` must be an array');
    }

    const data = await handleGrantType(eventRequest, client, options);

    const token = validateTokenModel(data, {
      allowExtendedTokenAttributes: options.allowExtendedTokenAttributes
    });

    const tokenResponse = createTokenResponse(token);

    return tokenResponse;
  } catch (error) {
    throw new OAuthError(error);
  }
}