# v3 constraint counts per optimisation level (circom 2.2.3, circomlib 2.0.5)

`integrated_access_v3.circom`: --O0 8133 non-linear + 15456 linear; --O1 (circom default, the
figure in p2-plan §1) 8116 + 1529; --O2 4935 + 0. All: 1 public input (`root`, witness slot 1),
0 outputs, 17 private inputs. --O0 has no `-1` entries in the .sym; --O1 already merges
(`main.leaf`, `merkle.hashers[0].out` are -1), so tamper tests need the O0 build.
Asserted in `circuits/test/v3.test.js`; "linear" = A or B empty, matches circom's printout.
Each level compiles in ~2 s. See [[v3-one-violated-row-tamper]], [[constraint-counts-o2]].
