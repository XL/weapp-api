class APIError extends Error {
  constructor(code, message) {
    super(message);
    if (code) this.code = code;
  }
}

module.exports = {APIError};
