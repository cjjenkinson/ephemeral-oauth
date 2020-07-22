const {
  InvalidArgumentError,
} = require('../errors');
const url = require('url');

module.exports = ({
  code,
  redirectUri,
}) => {
  if (!code) {
    throw new InvalidArgumentError('Missing parameter: `code`');
  }

  if (!redirectUri) {
    throw new InvalidArgumentError('Missing parameter: `redirectUri`');
  }

  const uri = url.parse(redirectUri, true);

  uri.query.code = code;
  uri.search = null;

  return uri;
}