const { InvalidArgumentError } = require('./utils/errors');

const handleAuthenticate = require('./handlers/authenticate');
const handleAuthorize = require('./handlers/authorize');
const handleToken = require('./handlers/token');

const createOAuth2Handler = (options) => {
  if (!options.model) {
    throw new InvalidArgumentError('`model` is a required option configuration');
  }

  const authenticate = async (event) => handleAuthenticate(event, options);
  const authorize = async (event) => handleAuthorize(event, options);
  const token = async (event) => handleToken(event, options);

  return {
    authenticate,
    authorize,
    token,
  }
}

module.exports = createOAuth2Handler;