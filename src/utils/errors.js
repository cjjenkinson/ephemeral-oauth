class InvalidArgumentError extends Error {}
class InvalidRequestError extends Error {}
class InvalidClientError extends Error {}
class ServerError extends Error {}

module.exports = {
  InvalidArgumentError,
  InvalidRequestError,
  InvalidClientError,
  ServerError
}