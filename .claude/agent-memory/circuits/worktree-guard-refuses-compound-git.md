# Worktree guard refuses compound commands that mention git

In an isolated agent worktree, a Bash call is refused when it contains `git` inside a loop or
`bash -c`, when it pipes/redirects a script run (`bash x.sh 2> log`), or even when a compound
command names a file like `.gitattributes`. Run git commands plain, one per call
(`git check-ignore --no-index -v <path>` per path), invoke scripts directly
(`circuits/scripts/x.sh ...`), and write files with the Write tool rather than heredoc chains.
Child processes spawned from node tests are not affected. Also refused (G1-S1-CIRC-036): a shell
`for` loop that runs `circom` on `$f`, `$HOME` inside a compound circom call, `cd` into a computed
dir before git, multi-heredoc chains, the `time` keyword, and `rm -rf` on /tmp paths (permission).
Put loops in a node script in the scratchpad and run it with `node <abs path>`. See [[p2-setup-scripts-layout]].
Also refused (G1-S1-CIRC-037): a `python3 - <<EOF` script that edits a file in the worktree; use Edit/Write instead.
