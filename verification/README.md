# APFS release evidence

Run the checker with Python 3.11 or later and Git from a clean candidate worktree. Keep the bundle and its transcripts outside that worktree.

```sh
python3 -B tools/check_release_evidence.py --root . --bundle "$evidence_dir/bundle.json"
```

The release command derives the mandatory method matrix for the milestone from the committed [obligation registry](obligations.json), then requires evidence for every invocation in the committed [release policy](release-profile.json). The current policy defines the format Kani invocation for A-V01. The full release command rejects the policy until the remaining required A-V01 and A-V02 methods have invocation definitions and transcript checks.

Use `--profile format-kani` to check one invocation independently. Run `bash crates/formats/apfs-format/verification/check.sh` from the candidate root with the pinned tools and capture stdout and stderr in one artifact. The bundle is a JSON array of [schema v1 records](evidence.schema.json). Set `commit` to the Git commit and `source_hash` to the SHA-256 of the archive below. It binds the committed source, runner, and verification policy to the record, with the Git line ending settings pinned across platforms.

```sh
git -c tar.umask=0002 -c core.autocrlf=false -c core.eol=lf archive --format=tar HEAD | shasum -a 256
```

Use the policy’s `command`, `features` and `bounds` values, and set `proof.theorem` to the profile name. Record the runner, measured duration, exact tool versions and exit code. Include a `transcript` artifact with its SHA-256 and a path relative to the bundle.

The checker verifies the clean candidate, record scope, artifact bytes, tool versions, and each expected Kani harness and cover count. The release process supplies the logs from the actual invocations. A profile pass and the standalone checker tests are partial evidence for A-VER-02-T01. [Checker tests](../tools/test_check_release_evidence.py)
