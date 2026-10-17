# seskafeabackendtests

A CI harness for a private project. This repository holds no product source code.

- The `qualify` workflow (manual dispatch only) checks out one private commit at run time with a read-only deploy key and runs that project's own qualification on GitHub-hosted Windows and macOS runners.
- `ci/guard.py` runs every command that can see the private source. It writes the command's output to files and prints only a one-line stage status, so job logs contain no source text.
- All outputs are encrypted with [age](https://github.com/FiloSottile/age) to the owner's public recipient (`ci/results.recipient`) before upload. The runner can encrypt but cannot decrypt.
- The `scrub` workflow checks each finished run's logs for private source text and canary tokens, uploads an encrypted report, and then deletes the logs.
- `mode=canary` is the log self-check. A canary run proves the guard hides output and that the audit detects a deliberately planted leak.

Pull requests and issues are not accepted.
