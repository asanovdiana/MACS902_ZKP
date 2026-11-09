"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

const mk = () => fs.mkdtempSync(path.join(os.tmpdir(), "zkgate-test-"));
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });

module.exports = { mk, rm };
