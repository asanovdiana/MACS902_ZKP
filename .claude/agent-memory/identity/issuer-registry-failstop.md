# Registry fails stop on persist error

`zk.createTree` is async (Poseidon init), so `issuer/src/registry.js` cannot rebuild a tree
synchronously to roll back a failed save. On a save error after the tree changed it sets `halted`
and every call throws 500 internal; restart reloads the last persisted state. Do not "fix" this
into a rollback without a sync tree factory. See [[issuer-key-dir-is-config]].
