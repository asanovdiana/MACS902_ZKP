"use strict";
// M2 registry: the profile-depth Merkle tree (circuits/lib createTree = zk-kit 1.1.0 + Poseidon),
// insert on issue, revoke = leaf <- 0, root history with timestamps and change kind, persistence.
//
// Fail-stop: if the state cannot be persisted after the in-memory tree changed, the registry
// halts (every call throws 500 internal) and the process must restart from the last persisted
// state. It never serves a root that is not on disk.
const zk = require("../../circuits/lib");
const { err } = require("./errors");

const STATE_VERSION = 1;

/**
 * Reference implementation of the staleness rule (issuer.api v1): accept proof root `root` iff it
 * is the current root, or it is in the history with gatewayNow - supersededAt <= windowSeconds and
 * every transition from it up to the current root is an insert. `history` is oldest first.
 * (The gateway implements the same rule in its own language.)
 */
function isRootAcceptable(history, root, gatewayNow, windowSeconds = 30) {
  let idx = -1;
  for (let i = history.length - 1; i >= 0; i--) {
    if (history[i].root === root) { idx = i; break; }
  }
  if (idx < 0) return false;
  if (idx === history.length - 1) return true;
  if (gatewayNow - history[idx].supersededAt > windowSeconds) return false;
  for (let j = idx; j < history.length - 1; j++) {
    if (history[j].supersededBy !== "insert") return false;
  }
  return true;
}

async function createRegistry({ profile, store, clock, historyRetentionSeconds = 900, onChange = () => {} }) {
  const p = zk.getProfile(profile);
  const capacity = 2 ** p.depth;
  const tree = await zk.createTree(p);
  const commitments = new Set();
  let leaves = []; // {commitment, leaf, revoked}
  let history = []; // {root, validFrom, supersededAt, supersededBy}
  let updatedAt;
  let halted = false;

  const currentRoot = () => tree.root.toString();

  const snapshot = () => ({ version: STATE_VERSION, profile: p.name, updatedAt, leaves, history });

  // ---- start: load + rebuild + verify -------------------------------------------------------
  const stored = store.load();
  if (stored) {
    if (stored.version !== STATE_VERSION) throw new Error("registry state: unsupported version");
    if (stored.profile !== p.name) throw new Error(`registry state was written by profile ${stored.profile}, configured profile is ${p.name}`);
    leaves = stored.leaves;
    history = stored.history;
    updatedAt = stored.updatedAt;
    for (const l of leaves) {
      tree.insert(l.revoked ? 0n : BigInt(l.leaf));
      commitments.add(l.commitment);
    }
    if (history.length === 0 || history[history.length - 1].root !== currentRoot()) {
      throw new Error("registry state: stored root does not match the tree rebuilt from stored leaves");
    }
  } else {
    const now = clock();
    updatedAt = now;
    history = [{ root: currentRoot(), validFrom: now, supersededAt: null, supersededBy: null }];
    store.save(snapshot());
  }

  // ---- helpers -------------------------------------------------------------------------------
  const live = () => {
    if (halted) throw err(500, "internal", "registry halted");
  };

  /** Appends the new root to the history; returns {prevRoot, at} for the change event. */
  function recordChange(kind) {
    const now = clock();
    const prev = history[history.length - 1];
    const prevRoot = prev.root;
    prev.supersededAt = now;
    prev.supersededBy = kind;
    history.push({ root: currentRoot(), validFrom: now, supersededAt: null, supersededBy: null });
    while (history.length > 1 && history[0].supersededAt !== null && now - history[0].supersededAt > historyRetentionSeconds) {
      history.shift();
    }
    updatedAt = now;
    return { prevRoot, at: now };
  }

  function persistOrHalt() {
    try {
      store.save(snapshot());
    } catch (e) {
      halted = true;
      throw e;
    }
  }

  function leafAt(i) {
    if (!Number.isSafeInteger(i) || i < 0 || i >= leaves.length) throw err(404, "unknown_leaf", "no such leaf index");
    return leaves[i];
  }

  return {
    profile: p.name,
    depth: p.depth,

    root() {
      live();
      return currentRoot();
    },
    updatedAt() {
      live();
      return updatedAt;
    },
    size() {
      live();
      return leaves.length;
    },

    /** "issued" | "revoked" for a leaf index (404 unknown_leaf otherwise). */
    leafStatus(index) {
      live();
      return leafAt(index).revoked ? "revoked" : "issued";
    },

    /** Pre-flight for the API: throws the 409s without mutating. */
    assertCanInsert(commitment) {
      live();
      if (commitments.has(commitment)) throw err(409, "duplicate_commitment", "commitment already issued");
      if (leaves.length >= capacity) throw err(409, "tree_full", "the registry has no free leaf");
    },

    /** Insert {commitment, leaf} at the next index; returns the index. */
    insert({ commitment, leaf }) {
      this.assertCanInsert(commitment);
      tree.insert(BigInt(leaf));
      const leafIndex = leaves.length;
      leaves.push({ commitment, leaf, revoked: false, issuedAt: clock(), revokedAt: null });
      commitments.add(commitment);
      const { prevRoot, at } = recordChange("insert");
      persistOrHalt();
      onChange("insert", { root: currentRoot(), prevRoot, leafIndex, at });
      return leafIndex;
    },

    /** leaf <- 0; returns the new root. */
    revoke(index) {
      live();
      const l = leafAt(index);
      if (l.revoked) throw err(409, "already_revoked", "leaf already revoked");
      tree.delete(index);
      l.revoked = true;
      l.revokedAt = clock();
      const { prevRoot, at } = recordChange("revoke");
      persistOrHalt();
      onChange("revoke", { root: currentRoot(), prevRoot, leafIndex: index, at });
      return currentRoot();
    },

    /** Path against the current root; JSON-integer pathIndices. 410 for a revoked leaf. */
    path(index) {
      live();
      const l = leafAt(index);
      if (l.revoked) throw err(410, "revoked", "credential revoked");
      const proof = zk.proofFor(tree, index);
      return {
        profile: p.name,
        leafIndex: proof.leafIndex,
        leaf: proof.leaf,
        root: proof.root,
        pathElements: proof.pathElements,
        pathIndices: proof.pathIndices.map(Number),
      };
    },

    /**
     * Admin listing (issuer.admin v1): index, status, leaf hash as in the tree (0 once revoked) and
     * timestamps. Never the commitment.
     */
    adminLeaves(from = 0, limit = 1000) {
      live();
      return leaves.slice(from, from + limit).map((l, k) => ({
        leafIndex: from + k,
        status: l.revoked ? "revoked" : "issued",
        leaf: l.revoked ? "0" : l.leaf,
        issuedAt: l.issuedAt ?? null,
        revokedAt: l.revokedAt ?? null,
      }));
    },

    /**
     * Path-compressed tree snapshot (issuer.admin v1): level l holds ceil(n / 2^l) nodes, the rest
     * of the level is zeros[l]. Reads zk-kit's internal level arrays (frozen outer array, no public
     * accessor for inner levels in 1.1.0).
     */
    async adminTree() {
      live();
      const n = leaves.length;
      const levels = [];
      for (let l = 0; l <= p.depth; l++) {
        const nodes = l === p.depth ? [currentRoot()] : tree._nodes[l].slice(0, Math.ceil(n / 2 ** l)).map(String);
        levels.push({ level: l, nodes });
      }
      const root = currentRoot(); // captured before the await: the snapshot stays consistent
      const zeros = tree.zeroes.map(String); // zk-kit lists levels 0..depth-1; the empty root is one more hash
      zeros.push(String(await zk.poseidon([zeros[p.depth - 1], zeros[p.depth - 1]])));
      return { profile: p.name, depth: p.depth, root, leafCount: n, zeros, levels };
    },

    /** Roots that were current at some time >= since, oldest first. */
    history(since = 0) {
      live();
      return history.filter((e) => e.supersededAt === null || e.supersededAt >= since).map((e) => ({ ...e }));
    },
  };
}

module.exports = { createRegistry, isRootAcceptable };
