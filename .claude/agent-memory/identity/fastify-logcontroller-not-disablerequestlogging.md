# Fastify 5.12: use LogController, not disableRequestLogging

`disableRequestLogging` top-level option emits FSTDEP023 in fastify >= 5.12. Use
`logController: new LogController({disableRequestLogging: true})` and log own fields in onResponse
(no URL/query/body in logs). Issuer tests run via `npm test --prefix issuer`; the root mocha spec
only covers `circuits/test`.
