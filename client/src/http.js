"use strict";
// Minimal JSON-over-HTTP helper shared by the issuer and gateway clients. Error messages name the
// peer and a code only; request bodies are never echoed.
const { ClientError } = require("./errors");

const stripSlash = (u) => String(u).replace(/\/+$/, "");

/**
 * @param {object} o  {fetch, method, url, body?, timeoutMs, who: "ISSUER"|"GATEWAY"}
 * @returns {Promise<{status:number, json:any}>}  2xx only; otherwise throws ClientError
 */
async function requestJson({ fetch, method, url, body, timeoutMs, who }) {
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: body === undefined ? { accept: "application/json" } : { accept: "application/json", "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (_) {
    throw new ClientError(`${who}_UNREACHABLE`, `${who.toLowerCase()} unreachable at ${stripSlash(new URL(url).origin)}`);
  }
  let json;
  const text = await res.text();
  try {
    json = text === "" ? {} : JSON.parse(text);
  } catch (_) {
    throw new ClientError(`${who}_BAD_RESPONSE`, `${who.toLowerCase()} returned a non-JSON reply (HTTP ${res.status})`, { status: res.status });
  }
  if (res.status >= 400) {
    const raw = json && json.error && typeof json.error.code === "string" ? json.error.code : "";
    const code = /^[a-z_]{1,40}$/.test(raw) ? raw : `http_${res.status}`;
    throw new ClientError(who === "ISSUER" ? code : `${who}_ERROR`, `${who.toLowerCase()} refused: ${code} (HTTP ${res.status})`, { status: res.status });
  }
  return { status: res.status, json };
}

module.exports = { requestJson, stripSlash };
