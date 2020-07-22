const { has, includes, assign } = require('lodash');

const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidClientError,
  UnauthorizedClientError,
  InvalidGrantError
} = require('../errors');

const is = require('../validator/is');

const { generateRandomToken } = require('../utils/generate-token');

const createAuthenticateHandler = require('./authenticate');
const createRedirectUri = require('../token/create-redirect-uri');

/**
 * Generate authorization code from the model or with util.
 */

const generateAuthorizationCode = async (client, user) => {
  if (options.model.generateAuthorizationCode) {
    return options.model.generateAuthorizationCode(client, user);
  }

  return generateRandomToken();
};

/**
 * Get authorization code lifetime.
 */
const getAuthorizationCodeLifetime = (authorizationCodeLifetime) => {
  const expires = new Date();

  expires.setSeconds(expires.getSeconds() + authorizationCodeLifetime);
  
  return expires;
};

/**
 * Get the client from the model.
 */
const getClient = async ({ body, query }, options) => {
  const clientId = body.client_id || query.client_id;

  if (!clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (!is.vschar(clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }

  const redirectUri = body.redirect_uri || query.redirect_uri;

  if (redirectUri && !is.uri(redirectUri)) {
    throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
  }

  const client = await options.model.getClient(clientId, null);

  if (!client) {
    throw new InvalidClientError('Invalid client: client credentials are invalid');
  }

  if (!client.grants) {
    throw new InvalidClientError('Invalid client: missing client `grants`');
  }

  if (!includes(client.grants, 'authorization_code')) {
    throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
  }

  if (!client.redirectUris || 0 === client.redirectUris.length) {
    throw new InvalidClientError('Invalid client: missing client `redirectUri`');
  }

  if (redirectUri && !includes(client.redirectUris, redirectUri)) {
    throw new InvalidClientError('Invalid client: `redirect_uri` does not match client value');
  }

  return client;
}

/**
 * Get scope from the request.
 */
const getScope = (eventRequest) => {
  const scope = eventRequest.body.scope || eventRequest.query.scope;

  if (!is.nqschar(scope)) {
    throw new InvalidScopeError('Invalid parameter: `scope`');
  }

  return scope;
}


/**
 * Get state from the request.
 */
const getState = async (eventRequest, options) => {
  const state = eventRequest.body.state || eventRequest.query.state;

  if (!options.allowEmptyState && !state) {
    throw new InvalidRequestError('Missing parameter: `state`');
  }

  if (!is.vschar(state)) {
    throw new InvalidRequestError('Invalid parameter: `state`');
  }

  return state;
}

/**
 * Get user by calling the authenticate handler.
 */
const getUser = async ({ headers, body, query }, options) => {
  if (!options.authenticateHandler) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `authenticateHandler()`');
  }

  const response = options.authenticateHandler(request, response);

  const user = response.headers['user'];

  if (!user) {
    throw new ServerError('Server error: `handle()` did not return a `user` object');
  }

  return user;
}

const getRedirectUri = (eventRequest, client) => {
  return eventRequest.body.redirect_uri || eventRequest.query.redirect_uri || client.redirectUris[0];
};

const saveAuthorizationCode = async (authorizationCode, expiresAt, scope, client, redirectUri, user) =>{
  const code = {
    authorizationCode: authorizationCode,
    expiresAt: expiresAt,
    redirectUri: redirectUri,
    scope: scope
  };

  return options.model.saveAuthorizationCode(code, client, user);
};

/**
 * Get response type.
 */
const getResponseType = (eventRequest) => {
  const responseType = eventRequest.body.response_type || eventRequest.query.response_type;

  if (!responseType) {
    throw new InvalidRequestError('Missing parameter: `response_type`');
  }

  if (!has(responseTypes, responseType)) {
    throw new UnsupportedResponseTypeError('Unsupported response type: `response_type` is not supported');
  }

  return responseTypes[responseType];
};

/**
 * Build a error response that redirects the user-agent to the client-provided url.
 */
const createErrorRedirectUri = (redirectUri, error) => {
  const uri = url.parse(redirectUri);

  uri.query = {
    error: error.name
  };

  if (error.message) {
    uri.query.error_description = error.message;
  }

  return uri;
};

const createAuthorizationCodeResponse = (redirectUri, state) => {
  redirectUri.query = redirectUri.query || {};

  if (state) {
    redirectUri.query.state = state;
  }
  
  return {
    statusCode: 301,
    headers: {
      Location: url.format(redirectUri)
    }
  };
}

module.exports = async (event, config) => {
  try {
    const options = Object.assign({
      allowEmptyState: config.allowEmptyState || false,
      authenticateHandler: config.authenticateHandler || createAuthenticateHandler(config),
      authorizationCodeLifetime: config.authorizationCodeLifetime ||  5 * 60, // 5 minutes
      ...config,
    });

    if (!options.authenticateHandler) {
      throw new InvalidArgumentError('Invalid argument: options does not implement `authenticateHandler()`');
    }

    if (!options.authorizationCodeLifetime) {
      throw new InvalidArgumentError('Missing parameter: `authorizationCodeLifetime`');
    }
  
    if (!options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }
  
    if (!options.model.getClient) {
      throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
    }
  
    if (!options.model.saveAuthorizationCode) {
      throw new InvalidArgumentError('Invalid argument: model does not implement `saveAuthorizationCode()`');
    }

    // Parse event request
    const eventRequest = parseAWSEvent(event);

    const expiresAt = getAuthorizationCodeLifetime(options.authorizationCodeLifetime);

    const client = await getClient(eventRequest);

    const user = await getUser(eventRequest);

    const uri = getRedirectUri(eventRequest, client);

    const scope = getScope(eventRequest);

    const authorizationCode = await generateAuthorizationCode(client, user, null);

    const state = getState(eventRequest);

    await saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user)

    const redirectUri = createRedirectUri(authorizationCode, uri);
  
    const response = createAuthorizationCodeResponse(redirectUri, state);

    return response;
  } catch (error) {
    const redirectUri = createErrorRedirectUri(uri, error, state);

    const response = createAuthorizationCodeResponse(redirectUri, state);

    throw new OAuthError({
      message: error.message,
      context: {
        location: response.headers.Location
      }
    });
  }
}