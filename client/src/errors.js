"use strict";
// One error type for the whole client. `code` is stable and machine-readable; `message` is for
// humans and never contains secrets, salts, signatures, paths or issuer-supplied free text beyond
// a short code. `reasons` (policy refusals) carry the user's own attribute values and are for local
// display only (floor 7).

class ClientError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = "ClientError";
    this.code = code;
    if (extra.status !== undefined) this.status = extra.status;
    if (extra.reasons !== undefined) this.reasons = extra.reasons;
  }
}

/** Convert an AccessInputError from circuits/lib (same code/reasons surface) into a ClientError. */
function fromLib(e) {
  if (e instanceof ClientError) return e;
  if (e && e.name === "AccessInputError") return new ClientError(e.code, e.message, { reasons: e.reasons });
  return e;
}

module.exports = { ClientError, fromLib };
