"use strict";
// Test helper: the admin assigns integer attributes; tests may write v4 role/dept as labels.
const zk = require("../../../circuits/lib");

function toInts(profile, attrs) {
  const out = { ...attrs };
  if (profile === "v4") {
    if (typeof out.role === "string") out.role = zk.ROLES[out.role];
    if (typeof out.dept === "string") out.dept = zk.DEPTS[out.dept];
  }
  return out;
}

module.exports = { toInts };
