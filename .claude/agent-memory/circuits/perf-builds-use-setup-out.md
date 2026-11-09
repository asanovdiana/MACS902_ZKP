# Throwaway setups: override SETUP_OUT, use a distinct name

`scripts/setup.sh` writes `<name>.verification_key.json` + manifest into `SETUP_OUT`
(default `circuits/setup/`, which is committed). `perf/measure.js` runs it with
`SETUP_OUT=build/perf/setup` and names `perf_access_<d>`, so benchmark keys never appear in
`git status` nor clobber the committed `access_16` keys. It passes
`PTAU=setup/ptau/pot15_DEV-ONLY_final.ptau` when present to skip ptau.sh's lookup. One setup at
~7-10k constraints takes ~70 s here.
See [[ptau-dev-fallback]].
