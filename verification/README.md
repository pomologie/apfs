# APFS release evidence

Run the checker with Python 3.11 or later and Git from a clean candidate worktree. Keep the bundle and its transcripts outside that worktree.

```sh
python3 -B tools/check_release_evidence.py --root . --bundle "$evidence_dir/bundle.json"
```

The release command derives the mandatory method matrix for the milestone from the committed [obligation registry](obligations.json), then requires evidence for every invocation in the committed [release policy](release-profile.json). The policy defines the format Kani invocation for A-V01, the checkpoint TLC invocation for A-V02, and a partial checksum differential invocation for A-V01. The full release command requires complete profiles for all active methods.

Use `--profile` with a profile name to check one invocation independently. Run the profile command from the candidate root with the pinned tools and capture stdout and stderr in one artifact. The bundle is a JSON array of [schema v1 records](evidence.schema.json). Set `commit` to the Git commit and `source_hash` to the SHA-256 of the archive below. It binds the committed source, runner, and verification policy to the record, with the Git line ending settings pinned across platforms.

```sh
git -c tar.umask=0002 -c core.autocrlf=false -c core.eol=lf archive --format=tar HEAD | shasum -a 256
```

Use the policy’s `command`, `features` and `bounds` values. Record the runner, measured duration, exact tool versions and exit code. Include a `transcript` artifact with its SHA-256 and a path relative to the bundle. For Kani and TLC profiles, set `proof.theorem` to the profile name.

The format profile uses `bash crates/formats/apfs-format/verification/check.sh`. The checker verifies each required Kani harness and cover count.

The `format-checksum-differential` profile uses `bash crates/formats/apfs-format/verification/check-checksum.sh`. It requires all seven named native fixture results with their expected wire checksums, plus every uniform and single changed word case across the five admitted sizes. The comparison uses the independent weighted-sum oracle in the integration tests. This covers the Fletcher-64 arithmetic subset of A-V01. Differential metadata admission and broader property testing remain separate evidence.

The checkpoint profile uses `bash crates/container/apfs-container/verification/models/check-evidence.sh`. Set `TLA2TOOLS_JAR` to the pinned TLA+ Tools v1.7.4 JAR and use Java 21.0.8. The runner validates the JAR digest, checks the committed model, and checks a temporary model with the documented wrong-selection witness. Record the profile seed as the schema string `"0"` and include `states` and `distinct_states` from the policy in `proof`. The checker verifies the full state graph, temporal check, and expected invariant violation with a counterexample.

The release process supplies the logs from the actual invocations. Profile passes and the standalone checker tests are partial evidence for A-VER-02-T01. [Checker tests](../tools/test_check_release_evidence.py)
