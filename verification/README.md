# APFS release evidence

Run the checker with Python 3.11 or later and Git from a clean candidate worktree. Keep the bundle and its transcripts outside that worktree.

```sh
python3 -B tools/check_release_evidence.py --root . --bundle "$evidence_dir/bundle.json"
```

The release command derives the mandatory method matrix for the milestone from the committed [obligation registry](obligations.json), then requires evidence for every invocation in the committed [release policy](release-profile.json). The policy defines the format Kani invocation for A-V01, the checkpoint TLC invocation for A-V02, and partial invocations for A-V01 checksum comparison, generated and directed properties, and native bootstrap replay. The full release command requires complete profiles for all active methods.

Use `--profile` with a profile name to check one invocation independently. Run the profile command from the candidate root with the pinned tools and capture stdout and stderr in one artifact. The bundle is a JSON array of [schema v1 records](evidence.schema.json). Set `commit` to the Git commit and `source_hash` to the SHA-256 of the archive below. It binds the committed source, runner, and verification policy to the record, with the Git line ending settings pinned across platforms.

```sh
git -c tar.umask=0002 -c core.autocrlf=false -c core.eol=lf archive --format=tar HEAD | shasum -a 256
```

Use the policy’s `command`, `features` and `bounds` values. Record the runner, measured duration, exact tool versions and exit code. Include a `transcript` artifact with its SHA-256 and a path relative to the bundle. For Kani and TLC profiles, set `proof.theorem` to the profile name.

The format profile uses `bash crates/formats/apfs-format/verification/check.sh`. The checker verifies each required Kani harness and cover count.

The `format-checksum-differential` profile uses `bash crates/formats/apfs-format/verification/check-checksum.sh`. It requires all seven named native fixture results with their expected wire checksums, plus every uniform and single changed word case across the five admitted sizes. The comparison uses the independent weighted-sum oracle in the integration tests. This covers the Fletcher-64 arithmetic subset of A-V01. Differential metadata admission and broader property testing remain separate evidence.

The `bootstrap-properties` profile runs the [deterministic bootstrap boundary matrix](../crates/container/apfs-container/tests/bootstrap_properties.rs). It compares NXSB admission and range endpoints against widened arithmetic, checks all header and checksum window prefix lengths through 64 bytes, and adds each of the 63 other feature bits to the supported native feature word. The checker requires a row for every supported block size and the named prefix, checksum and feature cases. This profile covers selected bootstrap boundaries. Broader generated input and checkpoint area combinations are separate evidence.

The `bootstrap-native` profile replays the retained 4 KiB-block Sonoma fixture with `bash crates/filesystem/apfs-reader/verification/check-native-bootstrap.sh`. Set `fixture_hash` to the policy’s `native_fixture.ledger_sha256` value. The runner verifies the acquisition ledger in LF form and the hashes of the retained metadata blocks, block zero, and filesystem root. The checker binds the transcript to the recorded successful Apple `fsck_apfs -n` invocation, its XID 4 result, and the original image digest. It also requires a fresh production replay with the same checkpoint, 64 MiB extent, wire checksum, and exact read counts for each typed bootstrap refusal. The Apple invocation comes from the fixture’s recorded acquisition. The runner uses the retained blocks and needs no mount. This partial native profile covers the populated bootstrap case. [Acquisition ledger](../crates/filesystem/apfs-reader/tests/fixtures/sonoma-populated-fsroot.json) · [Replay tests](../crates/filesystem/apfs-reader/tests/view/bootstrap.rs)

The `locator-properties` profile runs [generated NXSB locator cases](../crates/formats/apfs-format/tests/locator_properties.rs) with Proptest 1.12.0 and the schema seed string `"7"`. It checks both layouts and all five supported sizes. Each layout and block-size pair runs 64 cases for each of seven locator scenarios. The widened model decides admission, validates the decoded fields and compares the checked physical byte range. Fragmented locators are recognized by the codec. Opening a fragmented container remains outside the supported profile. This is the generated locator subset of A-V01 property evidence and remains separate from the bootstrap prefix matrix.

The checkpoint profile uses `bash crates/container/apfs-container/verification/models/check-evidence.sh`. Set `TLA2TOOLS_JAR` to the pinned TLA+ Tools v1.7.4 JAR and use Java 21.0.8. The runner validates the JAR digest, checks the committed model, and checks a temporary model with the documented wrong-selection witness. Record the profile seed as the schema string `"0"` and include `states` and `distinct_states` from the policy in `proof`. The checker verifies the full state graph, temporal check, and expected invariant violation with a counterexample.

The `checkpoint-model-properties` profile compares production selection and diagnostics with the [Rust reference model](../crates/container/apfs-container/verification/checkpoint_selection.rs). It requires every pair of earlier and latest states under automatic selection, exact XID 1, and exact XID 2. The 147 cases share two candidates and one wrapped descriptor-ring fixture. They cover this bounded A-V02 property and reference-comparison subset. More candidate counts, ring placements and broader independent comparisons remain separate evidence.

The release process supplies the logs from the actual invocations. Profile passes and the standalone checker tests are partial evidence for A-VER-02-T01. [Checker tests](../tools/test_check_release_evidence.py)
