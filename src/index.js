const { InvalidArgumentError } = require('./errors');

const handleAuthenticate = require('./handlers/authenticate');
const handleAuthorize = require('./handlers/authorize');
const handleToken = require('./handlers/token');

const createOAuth2Handler = (options) => {
  if (!options.model) {
    throw new InvalidArgumentError('`model` is a required configuration option');
  }

  const authenticate = async (event, config) => handleAuthenticate(event, options, config);
  const authorize = async (event, config) => handleAuthorize(event, options, config);
  const token = async (event, config) => handleToken(event, options, config);

  return {
    authenticate,
    authorize,
    token,
  }
}

module.exports = createOAuth2Handler;