"use strict";
// Ported unchanged in behaviour from the circuits prototype (G1-S1-CIRC-002) by
// G1-S1-CIRC-036. See circuits/scripts/MUTATION.md.
// Mutant generation for one constraint site.
//
// M1 (required by floor 1) removes the constraint while keeping the program well-formed:
//   `a === b;`   -> `{ }`        an empty block, legal wherever a statement is (a bare `;` is
//                                 NOT legal circom, e.g. as an unbraced for-loop body)
//   `s <== e;`   -> `s <-- e;`   s is still assigned by the witness generator, but nothing
//   `e ==> s;`   -> `e --> s;`   constrains it: the classic under-constrained bug.
// Line count is preserved so compiler messages still point at the original line numbers.

function mutantsFor(site) {
  if (site.op === "===") {
    return [{ kind: "M1", site, description: "delete the === constraint", replace: [site.start, site.end, "deleted"] }];
  }
  const to = site.op === "<==" ? "<--" : "-->";
  return [{ kind: "M1", site, description: `${site.op} -> ${to} (assigned, unconstrained)`, replace: [site.opStart, site.opEnd, to] }];
}

function applyMutant(src, mutant) {
  const [a, b, what] = mutant.replace;
  if (what === "deleted") {
    const newlines = src.slice(a, b).split("\n").length - 1;
    return src.slice(0, a) + "{ /* MUTANT: constraint removed */ }" + "\n".repeat(newlines) + src.slice(b);
  }
  return src.slice(0, a) + what + src.slice(b);
}

/** The mutated statement as it reads in the report. */
function mutantText(mutant) {
  const { site } = mutant;
  if (mutant.replace[2] === "deleted") return "(deleted)";
  return site.text.replace(site.op, mutant.replace[2]);
}

module.exports = { mutantsFor, applyMutant, mutantText };
