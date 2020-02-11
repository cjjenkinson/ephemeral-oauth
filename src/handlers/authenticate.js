const {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidTokenError,
  UnauthorizedRequestError,
  LambdaError,
  OAuthError,
} = require('../errors');

const parseAWSEvent = require('../utils/parse-aws-event');

/**
 * Get the access token from the model
 */
const getAccessToken = async (token, options) => {
  const accessToken = await options.model.getAccessToken(token);

  if (!accessToken) {
    throw new InvalidTokenError('Invalid token: access token is invalid');
  }

  if (!accessToken.user) {
    throw new LambdaError('Lambda error: `getAccessToken()` did not return a `user` object');
  }

  return accessToken;
}

/**
 * Validate access token
 */
const validateAccessToken = async (accessToken) => {
  if (!(accessToken.accessTokenExpiresAt instanceof Date)) {
    throw new LambdaError('Lambda error: `accessTokenExpiresAt` must be a Date instance');
  }

  if (accessToken.accessTokenExpiresAt < new Date()) {
    throw new InvalidTokenError('Invalid token: access token has expired');
  }

  return accessToken;
}

const getBearerToken = (authenticationHeader) => {
  const matches = token.match(/Bearer\s(\S+)/);

  if (!matches) {
    throw new InvalidRequestError('Invalid request: malformed authorization header');
  }

  return matches[1];
}

/**
 * Get the token from the request header.
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.1
 */
const getTokenFromRequestHeader = (eventRequest) => {
  const authenticationHeader = eventRequest.headers['Authorization'];

  return getBearerToken(token);
}

/**
 * Get the token from the request body
 *
 * "The HTTP request method is one for which the request-body has defined semantics.
 * In particular, this means that the "GET" method MUST NOT be used."
 *
 * @see http://tools.ietf.org/html/rfc6750#section-2.2
 */
const getTokenFromRequestBody = (eventRequest) => {
  if (eventRequest.method === 'GET') {
    throw new InvalidRequestError('Invalid request: token may not be passed in the body when using the GET verb');
  }

  const isValidContentType = (eventRequest.headers['Content-Type'] === 'application/x-www-form-urlencoded');

  if (!isValidContentType) {
    throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded');
  }

  return eventRequest.body.access_token;
}

/**
 * Get the token from the header or body, depending on the request.
 *
 * @see https://tools.ietf.org/html/rfc6750#section-2
 */
const getTokenFromRequest = (eventRequest) => {
  const headerToken = eventRequest.headers['Authorization'];
  const bodyToken = eventRequest.body.access_token;

  if (headerToken && bodyToken) {
    throw new InvalidRequestError('Invalid request: only one authentication method is allowed');
  }

  if (headerToken) {
    return getTokenFromRequestHeader(eventRequest);
  }

  if (bodyToken) {
    return getTokenFromRequestBody(eventRequest);
  }

  throw new UnauthorizedRequestError('Unauthorized request: no authentication given');
}

const authenticate = async (eventRequest, options) => {
  try {
    const token = getTokenFromRequest(eventRequest);

    const accessToken = await getAccessToken(token, options);

    const accessTokenResponse = validateAccessToken(accessToken);

    return accessTokenResponse
  } catch (error) {
    // TODO
    // if (error instanceof UnauthorizedRequestError) {
    //   return {
    //      headers: { 'WWW-Authenticate', 'Bearer realm="Service" }
    //    }
    // }

    if (!(error instanceof OAuthError)) {
      throw new LambdaError(error);
    }

    throw error;
  }
}

const authenticateByAuthoriser = async (event, options) => {
  try {
    const token = getBearerToken(event.authorisationToken);

    const accessToken = await getAccessToken(token, options);

    const accessTokenResponse = validateAccessToken(accessToken);

    return accessTokenResponse
  } catch (error) {
    if (!(error instanceof OAuthError)) {
      throw new LambdaError(error);
    }

    throw error;
  }
}

module.exports = async (event, options) => {
  try {
    if (!options.model) {
      throw new InvalidArgumentError('Missing parameter: `model`');
    }

    if (!options.model.getAccessToken) {
      throw new InvalidArgumentError('Invalid argument: model does not implement `getAccessToken()`');
    }

    if (options.isAuthoriser) {
      const response = await authenticateByAuthoriser(event, options);

      return response;
    }

    // Parse AWS lambda event
    const eventRequest = parseAWSEvent(event);

    const response = await authenticate(eventRequest, options);

    return response;
  } catch (error) {
    throw new OAuthError(error);
  }
}