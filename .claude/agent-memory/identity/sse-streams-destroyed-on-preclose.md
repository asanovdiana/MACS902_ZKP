# SSE streams must be destroyed on preClose

A hijacked `/admin/events` response keeps the socket active, so `app.close()` hangs unless a `preClose` hook destroys every client. Tests that listen and close rely on it. See [[zk-kit-tree-has-no-root-zero]].
