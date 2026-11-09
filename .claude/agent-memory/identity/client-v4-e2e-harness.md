# client v4 e2e harness

`client/test/helpers/realIssuer.js` starts the real issuer via `buildServer({config, logStream})`
+ `app.listen` on port 0 with temp key/data dirs (no admin token, so revoke is open). With
`challengeStub.js` (GET /challenge, POST /access, settable clock) the whole v4 flow runs in-process;
the CLI tests spawn `bin/zkgate` against the same servers. A warm v4 `prove` is about 1.0 s (first
1.3 s); the full client suite takes ~80 s. There is no Makefile in the tree yet, so the test command
is `npm test --prefix client`. See [[client-tests-use-node-test-and-stub-issuer]].
