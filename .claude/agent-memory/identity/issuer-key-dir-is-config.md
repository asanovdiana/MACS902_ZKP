# Issuer key dir is configuration

The guard hook refuses Read/Edit/Bash naming `issuer/keys/**`. Key dir = `ISSUER_KEY_DIR`
(default `issuer/keys`), file `issuer.key` (64 hex chars, 0600). Every test uses a temp dir via
`makeApp({keyDir})`; never name the real path in a command.
