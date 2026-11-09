# Attack Lab: build and run one attack at a time

Any enrolment or revocation changes the registry root, so a proof built earlier is `ROOT_NOT_CURRENT` for a strict gateway. `client/attacks` therefore builds then runs each attack before the next (CLI and tests). The reason code of a multi-violation attack depends on the gateway's check order (documented in `client/attacks/README.md`, proposal for P3). Circuit refusals are detected by `/Assert Failed/` in the snarkjs error; any other error is rethrown so an environment fault is not reported as a refusal. See [[crosscheck-suite-harness]].
