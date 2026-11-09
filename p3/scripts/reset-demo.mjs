// Resets demo state via the gateway admin API: challenges, nullifiers, sessions, events and
// (when the registry supports it) the registry tree. Usage: node scripts/reset-demo.mjs
const base = process.env.GATEWAY_URL ?? 'http://127.0.0.1:4000';
const token = process.env.OPERATOR_TOKEN ?? 'dev-operator-token-change-me-000000';
const login = await fetch(`${base}/api/operator/login`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ token }),
});
if (!login.ok) throw new Error(`operator login failed: ${login.status}`);
const cookie = login.headers.get('set-cookie').split(';')[0];
const r = await fetch(`${base}/api/admin/demo/reset`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', cookie },
  body: '{}',
});
console.log(r.status, await r.text());
