# safety — agent memory

One fact per file in this directory; one line here per fact, newest last. Link related facts with
`[[filename-without-extension]]`. Write a fact when something cost you time to discover and would
cost the next session the same: an endpoint quirk, a tool that lied, a constraint the code does not
state.

Do not record what the repository already says — structure, history, or anything in `CLAUDE.md`.

- [Committed wasm is a fast witness oracle](committed-wasm-is-a-fast-witness-oracle.md) — no compile; silence console; extra inputs throw.
- [TEST-ONLY issuer key is derivable](test-only-issuer-key-is-derivable.md) — sha256(seedLabel) = fixtures' pinned key; SR-07.
- [Open enrolment voided floors 2, 3, 5](open-enrolment-voids-floors-2-3-5.md) — SR-03 CLOSED by issuer.api v2; F2.14/F3.10 real.
- [Safety tier layout](safety-tier-layout.md) — run command, manifest rule, mkdtemp 0700 trap, no Makefile.
- [Gateway half pending](gateway-half-pending.md) — floors 2-5, 7 gateway half unsigned until P3.
- [v2 enrolment in the tier](v2-enrolment-in-the-tier.md) — makeIssuer has a token; enrolViaAdmin; integer attrs; bearer on admin.
- [Re-key provenance checks](rekey-provenance-checks.md) — ptau offsets are section-7-relative; zkey verify vs ptau; 62 contributions.
- [Verifier workers hang node:test](verifier-workers-hang-node-test.md) — call verifier.terminate() in after/t.after or the tier hangs.
- [F9.06 superseded by F9.12](f906-superseded-by-f912.md) — computed todo on install; transcript must be committed or F9.12 is red.
