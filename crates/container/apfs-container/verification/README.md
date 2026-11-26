# APFS container verification

## A-V02 checkpoint selection

The [checkpoint selection model](checkpoint_selection.rs) compares the production container API with a reference policy for two transactions in a wrapped descriptor ring. It exercises 147 cases by crossing seven evidence states per transaction with automatic selection and exact requests for the earlier and latest XIDs. The model predicts the selected descriptor and XID, typed refusals, and ordered diagnostics from the injected evidence without parsing APFS bytes.

The test starts from [retained native fixture blocks](../tests/fixtures/native-apfs.json). It synthesizes the ring wrap and varies complete evidence, an absent or torn descriptor, a blank map, a map with the other XID, unsupported map flags, and an unavailable payload. This supplies synthetic evidence for A-CONT-02-T01, a bounded reference model for T02, and directed regression coverage for T03. Fuzzing and native differential fixtures for damaged and wrapped rings remain open.

Run `cargo test --locked -p apfs-container --no-default-features --test checkpoints model::wrapped_selection_matches_reference_model` from the repository root.

In a disposable checkout, removing the transaction comparison from `read_maps` while retaining the map OID check made the test fail. The altered selector admitted the later descriptor with the earlier map XID. The model expected the earlier checkpoint, a rejection tied to the later descriptor, and a diagnostic for the newer bootstrap XID.

### Bounded TLC model

[CheckpointSelection.tla](models/CheckpointSelection.tla) covers three possible transaction IDs in two abstract ring slots, both scan origins, and automatic and exact selection. Each slot abstracts a descriptor and the outcome of verifying its associated map and required data. The ring stays fixed through a read. Missing and torn descriptors contribute no verified ID. A verified descriptor can have complete, missing, torn, wrong-XID, unsupported, or unreadable data. The model checks agreement with a declarative policy, requires rejected evidence for automatic fallback, and checks that selection terminates when the finite scan and validation steps can run. Exact selection stays bound to the requested XID. Unsupported or unreadable evidence and duplicate candidate identities are terminal at the transaction being considered.

The model's `Visit`, `TryCandidate`, and `Exhausted` steps correspond to the bounded scan, per-candidate validation, and empty-result paths in the [Rust selector](../src/checkpoint.rs). The [Rust comparison](checkpoint_selection.rs) covers the shared two-transaction fragment against actual bytes and diagnostics. The TLC scope abstracts map-block layout, checksum and payload decoding, detailed diagnostics, budgets, and the writer or crash protocol. The Rust fixture and native evidence carry their own bounds.

From this directory, run `bash models/check.sh /absolute/path/to/tla2tools.jar` with Java 21 and the [TLA+ Tools v1.7.4 release](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4). The runner pins the archive digest, uses one worker, seed 0, and fingerprint index 0, and removes its temporary state files. The check on Java 21.0.8 explored 16,396 states, including 13,196 distinct states at depth 6, with no invariant or temporal violations.

For the negative witness, allow `TryCandidate` to select XID 2 with a missing map during automatic selection when a complete earlier candidate exists. TLC reports `SelectionMatchesEvidence` violated. The Rust case `wrapped_checkpoint_requires_its_map_even_with_a_verified_descriptor` replays that condition and checks that the older candidate is selected with rejection and fallback diagnostics.

## A-V03 object-map lookup

The [object-map harness](kani/object_map.rs) covers the leaf selection portion of A-V03. It calls the production inclusive predecessor search and leaf visibility filter. The input is a prefix of at most eight strictly ordered unique keys. OIDs and transaction IDs use the full unsigned 64-bit range, and each leaf value can be live or deleted. An independent linear model filters by OID and requested XID, chooses the greatest eligible XID, and applies its tombstone.

The harness checks an empty leaf, a full eight-key leaf with future mappings, a query with only future versions, a tombstone over an older live version, and equality at the maximum XID. Sorting and uniqueness are prior format admission checks. Tree routing, physical address admission, object namespace validation, and consistency of a historical checkpoint or snapshot remain separate obligations. See the [repository obligation registry](../../../../verification/obligations.json).

Install Kani 0.68.0 and run `cargo kani setup`, then run `bash check.sh` from this directory.

For the negative witness, use a disposable checkout and change the search predicate from `key_at(middle)? <= key` to `key_at(middle)?.id <= key.id`. The altered search ignores the XID among versions of one OID. The live-mapping equivalence check must fail.
