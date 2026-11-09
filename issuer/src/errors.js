"use strict";
// API errors: {status, code}; messages are fixed strings and never echo request values.

class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

const err = (status, code, message) => new ApiError(status, code, message);

module.exports = { ApiError, err };
