const { InvalidArgumentError } = require('./utils/errors');

const handleToken = require('./handlers/token');

const createOAuth2Handler = (options) => {
  if (!options.model) {
    throw new InvalidArgumentError('`model` is a required option configuration');
  }

  const token = async (event) => handleToken(event, options);

  return {
    authenticate,
    authorize,
    token,
  }
}

module.exports = createOAuth2Handler;