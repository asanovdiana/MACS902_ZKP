"use strict";
// Minimal SSE client for tests: raw http, parses frames, wakes waiters on arrival.
const http = require("http");

function connectSse(url, { headers = {} } = {}) {
  const frames = [];
  const waiters = [];
  let buf = "";
  let request;
  const ready = new Promise((resolve, reject) => {
    request = http.get(url, { headers }, (r) => {
      r.setEncoding("utf8");
      resolve({ status: r.statusCode, headers: r.headers });
      r.on("data", (chunk) => {
        buf += chunk;
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const raw = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const f = { comment: null, id: null, event: null, data: null };
          for (const line of raw.split("\n")) {
            if (line.startsWith(":")) f.comment = line.slice(1).trim();
            else if (line.startsWith("id: ")) f.id = line.slice(4);
            else if (line.startsWith("event: ")) f.event = line.slice(7);
            else if (line.startsWith("data: ")) f.data = JSON.parse(line.slice(6));
          }
          frames.push(f);
          waiters.splice(0).forEach((w) => w());
        }
      });
      r.on("error", () => {});
    });
    request.on("error", reject);
  });
  const waitFor = async (pred, ms = 5000) => {
    const t0 = Date.now();
    for (;;) {
      const f = frames.find(pred);
      if (f) return f;
      if (Date.now() - t0 > ms) throw new Error("SSE timeout waiting for frame");
      await new Promise((r) => {
        waiters.push(r);
        setTimeout(r, 50);
      });
    }
  };
  return { ready, frames, waitFor, close: () => request && request.destroy() };
}

module.exports = { connectSse };
