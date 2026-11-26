# apfs verification plan

Start with bounded object and checkpoint parsing. The specification is older than many current profiles; unknown flags and unproven variants remain unsupported. No write or boot claims inferred from parsing. Fresh CoW-format image construction and persistent mutation have separate gates. Snapshot/clone reclamation and checkpoint publication require strict formal models and crash testing.

Read the shared ecosystem verification standard EVS-1 (`docs/architecture/ECOSYSTEM_VERIFICATION.md` after handoff). The following summarizes the repository-wide planning index at `verification/obligations.json`, which defines properties, assumptions, bounds, negative witnesses and required evidence methods. Implemented proof artifacts live in the owning crate’s `verification/` directory. All obligations are planned. Gate applies only to the activated supported profile; required proofs/tests must pass before that capability ships. Nonblocking advanced capabilities remain disabled if not qualified.

| ID | Activation | Scope | Required evidence |
|---|---|---|---|
| A-V01 | 0.1.0 | container | kani, property, fuzz, differential, native |
| A-V02 | 0.1.0 | checkpoint discovery | tlc, property, fuzz, differential, native |
| A-V03 | 0.2.0 | object mapping | kani, property, fuzz, differential |
| A-V04 | 0.2.0 | B-trees/volume selection | kani, property, fuzz, differential, native |
| A-V05 | 0.3.0 | ordinary file read | property, fuzz, differential, native |
| A-V06 | 0.4.0 | snapshots/shared/compressed reads | property, fuzz, differential, native |
| A-V07 | 0.4.0 | mapping proof | lean-linked, property, differential |
| A-V08 | 0.5.0 | fresh allocation | kani, property, differential, native |
| A-V09 | 0.5.0 | sealed plan | kani, property, fault, differential, native |
| A-V10 | 0.7.0 | CoW commit | tlc, fault, state-machine, differential, native |
| A-V11 | 0.8+ | snapshot/clone lifetime | tlc, lean-linked, state-machine, fault, native |
| A-V12 | later | crypto/advanced | property, fuzz, fault, differential, native |
| A-V13 | later | Charles/device adapter | miri, property, fault, integration |
| A-V14 | 1.0.0 | supported engine | lean-linked, property, mutation, differential |

## Invariant and proof details

### A-V01 — container
**Target:** apfs-format / checked geometry and object header.\
**Property:** Every admitted block range, count, object header and checksum window bounded; required unknown flags rejected before traversal.\
**Assumptions and initial bounds:** Kani full-width scalars + 0..8 entries, real object sizes via fuzz; checksum primitive independently tested.\
**Negative witness:** invalid block count causes large allocation or offset wrap.\
**Requirement links:** A-CONT-01.\
**Evidence:** kani, property, fuzz, differential, native; status planned.

The NXSB geometry subset and native-derived bootstrap rejection tests passed for A-CONT-01-T02. Kani covers full-width geometry arithmetic, standard object-header field decoding through 32 bytes and the checksum input window through 40 bytes. A separate weighted-sum oracle checks production Fletcher-64 arithmetic on seven native 4 KiB objects and synthetic buffers from 4 KiB to 64 KiB. The full obligation remains open. [Format and bootstrap evidence](../../crates/formats/apfs-format/verification/README.md)

### A-V02 — checkpoint discovery
**Target:** apfs-container / candidate selection.\
**Property:** Selected checkpoint is complete under qualified profile, validates descriptors/mappings/checksums and uses consistent XID; newest incomplete candidate not silently selected.\
**Assumptions and initial bounds:** TLC 3 candidates, 2 descriptor ring slots (plus larger fixtures), torn/missing descriptors, valid fallback explicitly allowed, not infer complete solely from XID.\
**Negative witness:** newest NXSB checksum valid but missing referenced checkpoint map.\
**Requirement links:** A-CONT-02.\
**Evidence:** tlc, property, fuzz, differential, native; status planned.

The bounded TLC model and the Rust comparison passed. The missing-map counterexample was reproduced in the altered model and replayed against the Rust fixture. Fuzzing and native differential evidence for damaged and wrapped rings remain open. [Checkpoint evidence](../../crates/container/apfs-container/verification/README.md#a-v02-checkpoint-selection)

### A-V03 — object mapping
**Target:** apfs-container / object-map resolution.\
**Property:** Virtual object resolves to visible version at requested XID (or qualified tombstone); physical/ephemeral/virtual identities never mixed; returned physical range bounded.\
**Assumptions and initial bounds:** Kani <=8 versions, full width XID comparisons; independent sorted-map model; native multi-version fixture.\
**Negative witness:** latest object map leaks future version into snapshot.\
**Requirement links:** A-CONT-03.\
**Evidence:** kani, property, fuzz, differential; status planned.

### A-V04 — B-trees/volume selection
**Target:** apfs-format + apfs-reader / TOC and tree validator.\
**Property:** Accepted node descriptor/key/value ranges valid and nonoverlapping as required by type; routing follows comparator; volume/root references consistent with selected checkpoint.\
**Assumptions and initial bounds:** Kani <=8 records and small byte windows; fixed/variable TOC types; native node-size fixtures and cycles.\
**Negative witness:** value offset sign interpreted incorrectly, overlaps TOC.\
**Requirement links:** A-CONT-04.\
**Evidence:** kani, property, fuzz, differential, native; status planned.

### A-V05 — ordinary file read
**Target:** apfs-reader / name lookup, logical extents and forks.\
**Property:** Each admitted file read exact logical bytes; holes zero only when explicit; xattrs/forks/link identities distinct; no stale volume or future XID reference.\
**Assumptions and initial bounds:** Small abstract trees <=12 files, <=8 extents; native case/hash collision/metadata fixtures.\
**Negative witness:** hash equality treated as full filename equality; unwritten extent returns unrelated bytes.\
**Requirement links:** A-READ-01, A-READ-02.\
**Evidence:** property, fuzz, differential, native; status planned.

### A-V06 — snapshots/shared/compressed reads
**Target:** apfs-reader / immutable view and snapshot selection.\
**Property:** Read of existing snapshot independent of newer commits; shared extents resolve correct logical owners; unsupported encrypted/compressed/role profiles reported not read as valid.\
**Assumptions and initial bounds:** Native snapshots/clone fixtures; exact supported flag ledger; read-only observation not refcount write proof.\
**Negative witness:** snapshot resolves through current root rather than pinned XID.\
**Requirement links:** A-READ-03, A-READ-04.\
**Evidence:** property, fuzz, differential, native; status planned.

### A-V07 — mapping proof
**Target:** apfs-container / pure map lookup, checked interval math.\
**Property:** Extracted Rust predecessor lookup and interval splitting refine mathematical map restricted to XID, correctly treating absent/tombstone states and full-width boundaries.\
**Assumptions and initial bounds:** Safe sequential subset; no proof of full B-tree graph/native implementation; external geometry validated.\
**Negative witness:** off-by-one on exact XID or tombstone version.\
**Requirement links:** A-CONT-03, A-CONT-04, A-READ-02.\
**Evidence:** lean-linked, property, differential; status planned.

### A-V08 — fresh allocation
**Target:** apfs-builder / object planner and free-space accounting.\
**Property:** Fresh qualified profile allocation covers each planned region exactly once; reserve required metadata/checkpoint objects; every object resolves in correct namespace and referenced blocks not free.\
**Assumptions and initial bounds:** Kani small 32-block geometry and 8 reservations; pure reference owner sets; no clone/snapshot mutation in fresh profile.\
**Negative witness:** spaceman free count includes live object map block.\
**Requirement links:** A-BUILD-01, A-BUILD-02.\
**Evidence:** kani, property, differential, native; status planned.

### A-V09 — sealed plan
**Target:** apfs-builder / finalized raw sector plan.\
**Property:** Stable deterministic raw plan has exact complete coverage, source bounds and output equivalence for random/serial reads; no metadata range changes after sealing.\
**Assumptions and initial bounds:** <=8 ranges Kani; immutable source contract and native data-container qualification; bounded payload memory.\
**Negative witness:** unplanned metadata gap written as zeros.\
**Requirement links:** A-BUILD-03.\
**Evidence:** kani, property, fault, differential, native; status planned.

### A-V10 — CoW commit
**Target:** apfs-writer / transaction persistence protocol.\
**Property:** Published checkpoint never references unpersisted required objects; after crash qualified reader sees consistent old/new complete checkpoint, not mixed versions; retired objects retained while reachable.\
**Assumptions and initial bounds:** TLC <=3 tx, 8 blocks, 2 retained roots, 2 ring slots; barriers, loss/torn descriptors, crash during recovery. Actual format-specific commit order and device model separately validated.\
**Negative witness:** checkpoint descriptor durable before object map/root.\
**Requirement links:** A-MUT-01.\
**Evidence:** tlc, fault, state-machine, differential, native; status planned.

### A-V11 — snapshot/clone lifetime
**Target:** apfs-writer / refcount and reachability model.\
**Property:** Every reachable block through current/checkpoint/snapshot/clone roots remains allocated; reclamation occurs only when no retained references or pending required use, accounting conservation incl deferred frees.\
**Assumptions and initial bounds:** TLC <=3 roots/2 snapshots/2 clones/8 blocks; Lean pure reference/lifetime accounting theorem linked to production helper before promotion; native tests.\
**Negative witness:** delete original releases block still referenced by clone.\
**Requirement links:** A-MUT-02.\
**Evidence:** tlc, lean-linked, state-machine, fault, native; status planned.

### A-V12 — crypto/advanced
**Target:** apfs optional security and advanced-profile code.\
**Property:** Only authenticated/qualified data and authorized credentials are accepted per exact algorithm profile; key material scoped/redacted; unsupported modes do not claim integrity; sealed volume check separate from Apple trust policy.\
**Assumptions and initial bounds:** External cryptographic primitives and Apple trust policies outside proof; security/legal review plus fixture-specific new obligations; no brute force or bypass.\
**Negative witness:** incorrect password/unsupported tag accepted; logs expose key.\
**Requirement links:** A-MUT-03.\
**Evidence:** property, fuzz, fault, differential, native; status planned.

### A-V13 — Charles/device adapter
**Target:** apfs device and kernel adapter / I/O ordering.\
**Property:** No pointer/offset escape, incorrect device barrier or stale view on actual qualified device; kernel-specific integration independently tested, not inferred from no_std.\
**Assumptions and initial bounds:** Device alignment, interrupt/scheduling/flush assumptions recorded; kernel harness once Charles interface exists.\
**Negative witness:** incompatible block size or failed flush ignored.\
**Requirement links:** A-MUT-04.\
**Evidence:** miri, property, fault, integration; status planned.

### A-V14 — supported engine
**Target:** apfs-format + apfs-container / selected pure verified helpers.\
**Property:** Production-linked proof of checked lookup and allocator arithmetic preserves exact namespace/range and allocated/free disjointness for validated states.\
**Assumptions and initial bounds:** Lean spec and extracted functions; format variants, disk I/O, snapshots and writer not implied unless separately qualified.\
**Negative witness:** integer overflow permits duplicate ownership.\
**Requirement links:** A-CONT-03, A-CONT-04, A-BUILD-02.\
**Evidence:** lean-linked, property, mutation, differential; status planned.

## Qualification work packages

- Define immutable pure core APIs and source/feature traceability before implementing proof harnesses. Start with range safety and binary framing, then reference set/map and traversal models.
- Create `tests/support` fault and fixture adapters, `fuzz` targets, Kani harnesses and `verification/models` for the actual registered scopes; preserve failing seeds as regression cases.
- Carry out implementation-linked Lean extraction on the first small eligible pure function before building broader theorem obligations. Failure to extract is not a proof; record alternate backend/evidence and amend the gate by explicit review before activation.
- Before shipping an activated protocol, check finite TLA+/TLC model and replay its actions/failures against production Rust. Native fixtures and actual fault/integration checks remain mandatory.
- Evidence is committed to the CI release report, never to a prefilled pass status. The present architecture pack does not contain a tested Rust implementation.

## Kernel portability release evidence
A-PORT-01 is an additional mandatory acceptance gate for every active kernel-facing crate, not a new claim of formal proof. Retain existing proof obligations. See TESTING.md and EES-1 §3a for exact profile compilation, feature graph, parity and negative leakage checks; actual kernel qualification remains separate.

`A-PORT-01-T01` passed for `apfs-core`, `apfs-format`, `apfs-container` and `apfs-reader` at `a494df4`. The pinned Rust 1.99.1 CI matrix ran `cargo check --locked -p PACKAGE --no-default-features --target TARGET` and the corresponding `cargo build` for `aarch64-unknown-none` and `x86_64-unknown-none`. A local Rust 1.99.1 replay passed `cargo build --locked --offline --release -p PACKAGE --no-default-features --target TARGET` for all eight pairs. The feature-boundary and semantic-parity cases retain their own acceptance records. [CI evidence](https://github.com/pomologie/apfs/actions/runs/45812476886)

`A-PORT-01-T02` passed locally with Rust 1.99.1. For each pair in the bare-metal matrix, `bash tools/check_kernel_dependencies.sh PACKAGE TARGET` admitted the expected normal target dependencies. `python3 -B tools/test_check_kernel_dependencies.py` passed on both targets. It admits a disposable graph where a host proc macro uses a standard-library dependency and rejects the same graph when a feature makes that dependency reachable on the target side. [Graph checker](../../tools/check_kernel_dependencies.sh) · [Regression fixture](../../tools/test_check_kernel_dependencies.py)

`A-PORT-01-T03` passed for the v0.1 container profile. EES-1 permits an unconditional `no_std` engine. The tests exercise the same engine through a simulated block device and a hosted `std::fs::File` adapter. Both see the same Sonoma 14.7.2 fixture blocks and match the native ledger for extent, selected transaction, descriptor, and volume metadata. They also agree on exact volume-superblock bytes and typed out-of-bounds, missing-checkpoint, and absent-XID results. The hosted file materializes only the retained fixture blocks in a temporary file. Rust 1.99.1 passed all 192 tests with `cargo test --locked --offline --workspace --no-default-features` on arm64 macOS. Both bare-metal release build matrices and the normal target dependency checks passed with the added fixture-only dependency. [Parity tests](../../crates/container/apfs-container/tests/checkpoint_selection/hosted_parity.rs) · [Native ledger](../../crates/container/apfs-container/tests/fixtures/native-apfs.json)

`A-PORT-01-T04` passed for the same eight kernel graphs and the separate macOS arm64 hosted profile. With Rust 1.99.1, `cargo check --locked --offline -p apfs-mounted --target aarch64-apple-darwin` and `cargo test --locked --offline --workspace --no-default-features` passed. The latter ran 189 tests. The macOS adapter resolves Darwin dependencies on macOS, and every kernel graph excludes the adapter and those dependencies. The adapter API is macOS-only. The current image engines each compile unconditionally as `no_std` and do not offer a second, `std`-enabled mode.
