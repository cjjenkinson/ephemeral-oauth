const {
  InvalidArgumentError,
} = require('../errors');

const modelAttributes = [
  'accessToken',
  'accessTokenExpiresAt',
  'refreshToken',
  'refreshTokenExpiresAt',
  'scope',
  'client',
  'user'
];

module.exports = (data, options) => {
  const model = {}

  if (!data.accessToken) {
    throw new InvalidArgumentError('Missing parameter: `accessToken`');
  }

  if (!data.client) {
    throw new InvalidArgumentError('Missing parameter: `client`');
  }

  if (!data.user) {
    throw new InvalidArgumentError('Missing parameter: `user`');
  }

  if (data.accessTokenExpiresAt && !(data.accessTokenExpiresAt instanceof Date)) {
    throw new InvalidArgumentError('Invalid parameter: `accessTokenExpiresAt`');
  }

  if (data.refreshTokenExpiresAt && !(data.refreshTokenExpiresAt instanceof Date)) {
    throw new InvalidArgumentError('Invalid parameter: `refreshTokenExpiresAt`');
  }

  model.accessToken = data.accessToken;
  model.accessTokenExpiresAt = data.accessTokenExpiresAt;
  model.client = data.client;
  model.refreshToken = data.refreshToken;
  model.refreshTokenExpiresAt = data.refreshTokenExpiresAt;
  model.scope = data.scope;
  model.user = data.user;

  if (options && options.allowExtendedTokenAttributes) {
    model.customAttributes = {};

    for (const key in data) {
      if (data[key] && (modelAttributes.indexOf(key) < 0)) {
        model.customAttributes[key] = data[key];
      }
    }
  }

  if (model.accessTokenExpiresAt) {
    model.accessTokenLifetime = Math.floor((model.accessTokenExpiresAt - new Date()) / 1000);
  }

  return model;
};
