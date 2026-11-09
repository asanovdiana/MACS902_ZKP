# Benchmarks share 4 vCPUs with peer agents' mutation sweeps

The sandbox has 4 logical cores and other agent sessions run on the same host. A peer's
`npm run mutate:access` (4 jobs of circom --O0 + mocha) pushed load to 12 and made AccessGate(8)
`fullProve` go from ~0.86 s (quiet) to ~2.4 s median. Before `npm run perf:measure`, check
`uptime` and `pgrep -f '^node scripts/mutate.js'` (anchor the pattern, or `pgrep -f` matches your
own waiting shell loop), and wait for quiet. `perf/measure.js` records the 1-minute load average
before/after each depth in the report. `kill` on a process is denied by auto mode (even your own);
stop your own background job with TaskStop.
See also [[snarkjs-verify-overhead]].
