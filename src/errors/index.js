class OAuthError extends Error {
  constructor(message, context) {
    super(message);
    this.expose = true;
    this.name = this.constructor.name;
    this.code = this.status = this.statusCode;
    this.context = context;

    Error.captureStackTrace(this, this.constructor);
  }
}

class AccessDeniedError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'access_denied';
    this.code = 400;
  }
}

class InsufficientScopeError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'insufficient_scope';
    this.code = 403;
  }
}

class InvalidArgumentError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'invalid_argument';
    this.code = 500;
  }
}

class InvalidClientError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'invalid_client';
    this.code = 400;
  }
}

class InavlidGrantError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'invalid_grant';
    this.code = 400;
  }
}

class InvalidRequestError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'invalid_request';
    this.code = 400;
  }
}

class InvalidScopeError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'invalid_scope';
    this.code = 400;
  }
}

class InvalidTokenError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'invalid_token';
    this.code = 401;
  }
}

class UnauthorizedClientError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'unauthorized_client';
    this.code = 400;
  }
}

class UnauthorizedRequestError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'unauthorized_request';
    this.code = 401;
  }
}

class UnsupportedGrantTypeError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'unsupported_grant_type';
    this.code = 400;
  }
}

class UnsupportedResponseTypeError extends OAuthError {
  constructor(message) {
    super(message);
    this.name = 'unsupported_response_type';
    this.code = 400;
  }
}

class ServerError extends OAuthError {
  constructor(message, context) {
    super(message);
    this.name = 'server_error';
    this.code = 503;
    this.context = context;
  }
}

module.exports = {
  OAuthError,
  AccessDeniedError,
  InsufficientScopeError,
  InvalidArgumentError,
  InvalidClientError,
  InavlidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  UnauthorizedClientError,
  UnauthorizedRequestError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
  ServerError,
}
