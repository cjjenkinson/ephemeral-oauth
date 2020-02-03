const qs = require('querystring');

const {
  InvalidRequestError
} = require('../utils/errors');

module.exports = ({
  headers,
  httpMethod: method,
  queryStringParameters: query,
  body,
}) => {
  if (method !== 'POST') {
    throw new InvalidRequestError('method must be POST');
  }

  // TODO
  // if (!headers.is('application/x-www-form-urlencoded')) {
  //   throw new InvalidRequestError('content must be application/x-www-form-urlencoded');
  // }

  return {
    headers,
    method,
    query,
    body: qs.parse(body),
  }
};