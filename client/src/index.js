"use strict";
// Public library API of the ZK Access Gate client (reused by the demo UI and the CLI).
const { ClientError } = require("./errors");
const { Wallet, fingerprint } = require("./wallet");
const { IssuerClient } = require("./issuerClient");
const { requestCredential, checkIssuedAttributes } = require("./enrol");
const { prove, prepareV3, prepareV4, shutdown, ARTEFACT_DIR } = require("./prover");
const { parseChallenge, fetchChallenge, submitProof } = require("./challenge");

module.exports = {
  ClientError,
  Wallet, fingerprint,
  IssuerClient,
  requestCredential, checkIssuedAttributes,
  prove, prepareV3, prepareV4, shutdown, ARTEFACT_DIR,
  parseChallenge, fetchChallenge, submitProof,
};
