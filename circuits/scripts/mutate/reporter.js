"use strict";
// Ported unchanged in behaviour from the circuits prototype (G1-S1-CIRC-002) by
// G1-S1-CIRC-036. See circuits/scripts/MUTATION.md.
// Mocha reporter used by the mutation harness: writes {passes, failures:[{fullTitle, err}]}
// to the file named by $MUTATE_RESULT_FILE. Keeps results off stdout, which tests may print to.
//
// With $MUTATE_FORBID (a RegExp source; the harness then runs mocha without --bail) the reporter
// does the bailing itself: it aborts the run at the first failure whose full title does NOT
// match, so a forbidden failure (a static source / constraint-count test, a hook) is recorded but
// never stops a later soundness test from running.
const fs = require("fs");
const Mocha = require("mocha");

const { EVENT_TEST_PASS, EVENT_TEST_FAIL, EVENT_RUN_END } = Mocha.Runner.constants;

class MutateReporter {
  constructor(runner) {
    const res = { passes: 0, failures: [] };
    const forbid = process.env.MUTATE_FORBID ? new RegExp(process.env.MUTATE_FORBID) : null;
    runner.on(EVENT_TEST_PASS, () => res.passes++);
    runner.on(EVENT_TEST_FAIL, (test, err) => {
      const fullTitle = test.fullTitle();
      res.failures.push({
        title: test.title,
        fullTitle,
        err: String((err && (err.stack || err.message)) || err).slice(0, 4000),
      });
      if (forbid && !forbid.test(fullTitle)) runner.abort();
    });
    runner.once(EVENT_RUN_END, () => {
      if (process.env.MUTATE_RESULT_FILE) fs.writeFileSync(process.env.MUTATE_RESULT_FILE, JSON.stringify(res));
    });
  }
}

module.exports = MutateReporter;
