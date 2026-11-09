# v3 Alice in the vectors is role 2 / clearance 2 on purpose

P1's v3 FileShareAccess needs role and clearance in {2,3}; those numbers are opaque (ADR 0008),
not D6 (2 = contractor). `vectors/v3` therefore gives Alice the v3 File Share TEST values 2/2 so a
v3 witness exists; Bob (2/1) and Carol (1/3) keep their D6 numbers and v3 rejects them. v3
attributes are unsigned, so the commitment/signature/leaf do not depend on them. v4 vectors use
real D6 values. Related: [[lib-v4-input-signal-names]].
