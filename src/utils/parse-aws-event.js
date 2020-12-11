const qs = require('querystring');

const {
  InvalidRequestError,
} = require('../errors');

module.exports = ({
  headers,
  httpMethod: method,
  queryStringParameters: query,
  body,
}) => {
  if (method !== 'POST') {
    throw new InvalidRequestError('method must be POST');
  }

  return {
    headers,
    method,
    query: qs.parse(query),
    body: JSON.parse(JSON.stringify(body)),
  };
};
