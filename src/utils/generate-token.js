const cryptoRandomString = require('crypto-random-string');

const generateRandomToken = () => {
  const token = cryptoRandomString({
    length: 256,
    type: 'base64'
  });

  return token;
};

module.exports = {
  generateRandomToken
}