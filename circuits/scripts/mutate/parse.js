"use strict";
// Ported unchanged in behaviour from the circuits prototype (G1-S1-CIRC-002) by
// G1-S1-CIRC-036. See circuits/scripts/MUTATION.md.
// Minimal Circom 2 lexer + statement splitter for the mutation harness.
//
// It does not build an AST. It only needs to (a) find every statement that carries a
// constraint operator (=== <== ==>) or a bare assignment (<-- -->), (b) know the statement's
// exact source span so it can be rewritten, and (c) know which template it belongs to and
// whether it sits under a loop or a conditional. A statement inside a loop is ONE site even
// though circom unrolls it many times.

const CONSTRAINT_OPS = new Set(["===", "<==", "==>"]);
const ARROW_OPS = new Set(["<--", "-->"]);
// Longest first, so `===` wins over `==` and `<==` over `<=`.
const PUNCT = [
  "===", "<==", "==>", "<--", "-->", "<<=", ">>=", "\\=",
  "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "++", "--", "+=", "-=", "*=", "/=", "%=",
  "^=", "&=", "|=", "**",
];
const HEADER_KEYWORDS = new Set(["for", "while", "if"]);
const BLOCK_KEYWORDS = new Set(["template", "function", "bus"]);
const DECL_KEYWORDS = new Set(["signal", "input", "output", "var", "component", "public"]);

/**
 * Tokenise. Comments are skipped (and, in `blanked`, replaced by spaces with newlines kept so
 * offsets and line numbers are preserved). Strings are single tokens, so a `===` inside a
 * `log("...")` is never a site.
 */
function lex(src) {
  const toks = [];
  const blanked = src.split("");
  let i = 0;
  const n = src.length;
  const blank = (a, b) => {
    for (let k = a; k < b; k++) if (blanked[k] !== "\n") blanked[k] = " ";
  };
  while (i < n) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      let j = src.indexOf("\n", i);
      if (j < 0) j = n;
      blank(i, j);
      i = j;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      let j = src.indexOf("*/", i + 2);
      j = j < 0 ? n : j + 2;
      blank(i, j);
      i = j;
      continue;
    }
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      toks.push({ t: "str", v: src.slice(i, j + 1), s: i, e: j + 1 });
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$]/.test(src[j])) j++;
      toks.push({ t: "id", v: src.slice(i, j), s: i, e: j });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < n && /[0-9A-Za-z_]/.test(src[j])) j++;
      toks.push({ t: "num", v: src.slice(i, j), s: i, e: j });
      i = j;
      continue;
    }
    const p = PUNCT.find((op) => src.startsWith(op, i)) || c;
    toks.push({ t: "op", v: p, s: i, e: i + p.length });
    i += p.length;
  }
  return { toks, blanked: blanked.join("") };
}

function lineAt(src, offset) {
  let line = 1;
  for (let k = 0; k < offset && k < src.length; k++) if (src[k] === "\n") line++;
  return line;
}

/** Skip a balanced (...) group starting at toks[i] (which must be "("); return index after it. */
function skipParens(toks, i) {
  let depth = 0;
  for (; i < toks.length; i++) {
    if (toks[i].v === "(") depth++;
    else if (toks[i].v === ")" && --depth === 0) return i + 1;
  }
  return i;
}

/**
 * Split into statements. Returns every simple statement (ends at `;` at bracket depth 0) with
 * its token range, template name and control context ("for", "while", "if", "else", or "").
 */
function statements(src) {
  const { toks, blanked } = lex(src);
  const out = [];
  const blocks = []; // { kind: "template"|"function"|"bus"|"ctl"|"plain", name, ctx }
  let pendingCtx = null; // context set by a header, applies to the next statement or block
  let pendingBlock = null; // template/function header awaiting its "{"
  const ctxNow = () => {
    for (let k = blocks.length - 1; k >= 0; k--) {
      if (blocks[k].ctx) return blocks[k].ctx;
      if (BLOCK_KEYWORDS.has(blocks[k].kind)) break;
    }
    return "";
  };
  const templateNow = () => {
    for (let k = blocks.length - 1; k >= 0; k--) if (BLOCK_KEYWORDS.has(blocks[k].kind)) return blocks[k];
    return null;
  };

  let i = 0;
  while (i < toks.length) {
    const t = toks[i];
    if (t.v === "{") {
      if (pendingBlock) {
        blocks.push(pendingBlock);
        pendingBlock = null;
      } else {
        blocks.push({ kind: pendingCtx ? "ctl" : "plain", ctx: pendingCtx || null });
      }
      pendingCtx = null;
      i++;
      continue;
    }
    if (t.v === "}") {
      blocks.pop();
      i++;
      continue;
    }
    if (t.v === ";") {
      pendingCtx = null;
      i++;
      continue;
    }
    if (t.t === "id" && HEADER_KEYWORDS.has(t.v) && toks[i + 1] && toks[i + 1].v === "(") {
      // An unbraced header nested in another keeps the innermost loop/if name, which is
      // what matters for the report ("this site is inside a loop").
      pendingCtx = t.v;
      i = skipParens(toks, i + 1);
      continue;
    }
    if (t.t === "id" && t.v === "else") {
      pendingCtx = "else";
      i++;
      continue;
    }
    if (t.t === "id" && BLOCK_KEYWORDS.has(t.v) && toks[i + 1] && toks[i + 1].t === "id") {
      // `template [custom|parallel] Name(args) {` / `function name(args) {` / `bus Name(...) {`
      let j = i + 1;
      while (j < toks.length && toks[j].t === "id" && toks[j + 1] && toks[j + 1].t === "id") j++;
      pendingBlock = { kind: t.v, name: toks[j].v };
      while (j < toks.length && toks[j].v !== "{") j++;
      i = j;
      continue;
    }
    // A simple statement: up to the `;` at bracket depth 0.
    const start = i;
    let depth = 0;
    let j = i;
    for (; j < toks.length; j++) {
      const v = toks[j].v;
      if (v === "(" || v === "[" || v === "{") depth++;
      else if (v === ")" || v === "]" || v === "}") {
        if (depth === 0) break; // malformed; stop before the closer
        depth--;
      } else if (v === ";" && depth === 0) break;
    }
    const endTok = j < toks.length && toks[j].v === ";" ? j : j - 1;
    const stmtToks = toks.slice(start, endTok + 1);
    let opIdx = -1;
    let d = 0;
    for (let k = 0; k < stmtToks.length; k++) {
      const v = stmtToks[k].v;
      if (v === "(" || v === "[" || v === "{") d++;
      else if (v === ")" || v === "]" || v === "}") d--;
      else if (d === 0 && (CONSTRAINT_OPS.has(v) || ARROW_OPS.has(v))) {
        opIdx = k;
        break;
      }
    }
    const tpl = templateNow();
    const s = stmtToks[0].s;
    const e = stmtToks[stmtToks.length - 1].e;
    out.push({
      toks: stmtToks,
      opIdx,
      op: opIdx >= 0 ? stmtToks[opIdx].v : null,
      start: s,
      end: e,
      line: lineAt(src, s),
      endLine: lineAt(src, e - 1),
      text: blanked.slice(s, e).replace(/\s+/g, " ").trim(),
      template: tpl ? tpl.name : null,
      templateKind: tpl ? tpl.kind : null,
      tplRef: tpl, // identity of the enclosing template block (two templates may share a name)
      context: pendingCtx || ctxNow(),
    });
    pendingCtx = null;
    i = endTok + 1;
  }
  return out;
}

/**
 * Every constraint-bearing statement (===, <==, ==>) — the mutation sites.
 * `file` is carried through to the site so reports can say file:line.
 */
function parseSites(src, file) {
  return statements(src)
    .filter((st) => CONSTRAINT_OPS.has(st.op))
    .map((st) => ({
      file,
      line: st.line,
      endLine: st.endLine,
      op: st.op,
      text: st.text,
      template: st.template,
      context: st.context,
      start: st.start,
      end: st.end,
      opStart: st.toks[st.opIdx].s,
      opEnd: st.toks[st.opIdx].e,
    }));
}

/** Signal paths (`a`, `c.out`, `c.in.x`) mentioned in a token list; bracket groups are skipped. */
function signalPaths(toks) {
  const paths = [];
  let k = 0;
  while (k < toks.length) {
    if (toks[k].t !== "id" || DECL_KEYWORDS.has(toks[k].v)) {
      k++;
      continue;
    }
    const parts = [toks[k].v];
    k++;
    for (;;) {
      if (toks[k] && toks[k].v === "[") {
        let d = 0;
        for (; k < toks.length; k++) {
          if (toks[k].v === "[") d++;
          else if (toks[k].v === "]" && --d === 0) break;
        }
        k++;
        continue;
      }
      if (toks[k] && toks[k].v === "." && toks[k + 1] && toks[k + 1].t === "id") {
        parts.push(toks[k + 1].v);
        k += 2;
        continue;
      }
      break;
    }
    paths.push(parts.join("."));
  }
  return paths;
}

/**
 * Floor 1, second clause: every `<--` / `-->` must be followed, within the same template, by an
 * `===` that references the assigned signal. Returns the violations (empty = pass).
 * With `{ allowArrowConstraint: true }` a later `<==`/`==>` that mentions the signal also counts
 * (circomlib's IsZero style); the default is the strict reading of the floor.
 */
function auditArrows(src, file, opts = {}) {
  const sts = statements(src);
  const checkOps = new Set(opts.allowArrowConstraint ? ["===", "<==", "==>"] : ["==="]);
  const violations = [];
  sts.forEach((st, idx) => {
    if (!ARROW_OPS.has(st.op) || st.templateKind !== "template") return;
    // Assigned side: left of <--, right of -->. The signal is the last path on that side
    // (skips `signal`, tags, etc.).
    const side = st.op === "<--" ? st.toks.slice(0, st.opIdx) : st.toks.slice(st.opIdx + 1);
    const paths = signalPaths(side.filter((t) => t.v !== ";"));
    const signal = paths[paths.length - 1];
    const checked = sts.slice(idx + 1).some(
      (later) => later.tplRef === st.tplRef && checkOps.has(later.op) && signalPaths(later.toks).includes(signal)
    );
    if (!checked) {
      violations.push({ file, line: st.line, template: st.template, signal, text: st.text });
    }
  });
  return violations;
}

module.exports = { lex, statements, parseSites, auditArrows, signalPaths, lineAt };
