/**
 * Validation rules.
 */

const rules = {
  NCHAR: /^[\u002D|\u002E|\u005F|\w]+$/,
  NQCHAR: /^[\u0021|\u0023-\u005B|\u005D-\u007E]+$/,
  NQSCHAR: /^[\u0020-\u0021|\u0023-\u005B|\u005D-\u007E]+$/,
  UNICODECHARNOCRLF: /^[\u0009|\u0020-\u007E|\u0080-\uD7FF|\uE000-\uFFFD|\u10000-\u10FFFF]+$/,
  URI: /^[a-zA-Z][a-zA-Z0-9+.-]+:/,
  VSCHAR: /^[\u0020-\u007E]+$/
};

/**
 * Export validation functions.
 */

module.exports = {

  /**
   * Validate if a value matches a unicode character.
   *
   * @see https://tools.ietf.org/html/rfc6749#appendix-A
   */

  nchar: (value) => rules.NCHAR.test(value),

  /**
   * Validate if a value matches a unicode character, including exclamation marks.
   *
   * @see https://tools.ietf.org/html/rfc6749#appendix-A
   */

  nqchar: (value) => rules.NQCHAR.test(value),

  /**
   * Validate if a value matches a unicode character, including exclamation marks and spaces.
   *
   * @see https://tools.ietf.org/html/rfc6749#appendix-A
   */

  nqschar: (value) => rules.NQSCHAR.test(value),

  /**
   * Validate if a value matches a unicode character excluding the carriage
   * return and linefeed characters.
   *
   * @see https://tools.ietf.org/html/rfc6749#appendix-A
   */

  uchar: (value) => rules.UNICODECHARNOCRLF.test(value),

  /**
   * Validate if a value matches generic URIs.
   *
   * @see http://tools.ietf.org/html/rfc3986#section-3
   */
  uri: (value) => rules.URI.test(value),

  /**
   * Validate if a value matches against the printable set of unicode characters.
   *
   * @see https://tools.ietf.org/html/rfc6749#appendix-A
   */

  vschar: (value) => rules.VSCHAR.test(value),
};
