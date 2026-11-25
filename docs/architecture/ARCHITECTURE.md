# apfs architecture

## Mission and constraints

A standalone Rust Apple File System implementation, initially read-only, then deterministic fresh image construction, later transactional writes and Charles integration. The dmgez APFS feature is optional and nonblocking for v1.0. APFS is a long-term independent filesystem project, not a dependency of HFS+ or a subcrate of dmgez. APFS on-disk format differs radically from HFS+, with separate container and filesystem layers, object addressing, checkpoints, transaction IDs, allocation/reference accounting and snapshots. Apple's 2020 reference (S12; pp. 7, 26, 44 are baseline architecture references) is not a complete modern macOS contract. Establish capability/evidence profiles with actual OS builds, starting with unencrypted single-store regular data volumes; target compatibility with Sequoia-era fixtures and later versions only after qualification. Do not imply access to proprietary code, keys or boot security. Read-only parsing is initially the safest useful milestone. Full encrypted, sealed, Fusion, boot, clones and transactional support require dedicated evidence and review. The default dmgez builder is HFS+; do not make APFS a dependency of dmgez's critical path.

## Workspace (target)

```text
apfs/
  apps/apfs-cli/                  # raw-container inspect, read, check, later build
  crates/
    foundation/apfs-core/         # I/O contracts, IDs, errors, limits, metadata
    formats/apfs-format/          # on-disk codecs, flags, object/tree records
    container/apfs-container/     # NXSB, checkpoints, omaps, object resolution
    filesystem/apfs-reader/       # volumes, dirs, inode, extents, attrs
    filesystem/apfs-builder/      # deterministic unencrypted fresh image construction
    filesystem/apfs-writer/       # later CoW transactions, allocation/refcounts
    platform/apfs-mounted/        # hosted Darwin descriptor and copy mechanisms
    security/apfs-crypto/         # later authorized volume crypto
    verification/apfs-check/      # when full consistency engine merits separation
  tests/fixtures/  tests/differential/  tests/compatibility/
  docs/  examples/  benches/  fuzz/  xtask/  .github/workflows/
  Cargo.toml  Cargo.lock  rust-toolchain.toml  AGENTS.md
```

Prefix all package names; verify registry availability before publishing. Start core, format, container, reader only. `format -> core`, `container -> format, core`, `reader -> container, format, core`, `builder -> format, core` and factored container-layout modules (avoid depending on full reader except testing), `writer -> format, container, reader` and later mutation components, `crypto` supplies only explicit storage/decryption interfaces to container/reader through lower-level contract, no reverse cycles. Verification reads typed container/volume views; no mutation/repair. CLI composes optional services. No dependency on HFS+, dmgez, third-party APFS backend, host Finder, or Charles. File/device adapters live behind `std`. `apfs-core`, `apfs-format`, `apfs-container`, `apfs-reader` and future `apfs-writer`/transaction logic must support `no_std + alloc` (format codecs prefer core alone), starting with their first release. `apfs-builder` and host adapters may use std; shared kernel algorithms may not. APFS will run in the Charles kernel, independently of the userspace Rust std port. Follow EES-1 §3a for mandatory bare-metal compile gates; actual kernel integration is separately qualified. Crypto API must not expose secrets in object types, diagnostics or test fixtures. No full APFS driver for P0.

The macOS-only mounted companion uses Darwin's kernel filesystem operations over caller-authorized descriptors. Its scoped unsafe ABI wrappers are separate from the portable APFS image engine. ExaCopy owns authorization, journal encodings, copy verification, and publication intent. [Mounted companion contract](../features/MOUNTED.md)

## Public API sketch

```rust
Container::open(source, OpenOptions) -> Result<ContainerView>
ContainerView::checkpoints(), volumes(), capabilities(), inspect()
ContainerView::open_volume(id, ViewSelector) -> Result<VolumeView>
// ViewSelector: selected qualified committed XID or explicit snapshot
VolumeView::lookup(parent, name), read_dir(parent, page), stat(node)
VolumeView::open_data(node), read_link(node), list_attrs(node), open_attr(node, key)
Builder::plan(tree, ContainerGeometry, VolumePolicy) -> Result<PlanDraft>
PlanDraft::identity(entry), bind_generated_payload(entry, source), seal() -> SealedPlan
SealedPlan::len(), read_exact_at(offset, buf), write_to(sink), ranges()
```

Use C2-C6 analogous library-local traits (no unnecessary cross-repo dependency). Distinct typed OID, XID, physical address, volume ID, logical offset; use signed/unsigned interpretation per field. `ContainerView` is immutable and tied to a particular source identity + selected complete checkpoint. Each volume/snapshot opens exact consistent object map view; never mix XIDs or assume current object locations across snapshots. Node handles include view ID, not just file ID. Multi-volume selection explicit. No host paths in core. A fresh builder produces a valid committed checkpoint and complete metadata for a clean ordinary data volume, not a generic mounted writable volume. `MutableContainer`/`Transaction` later, separate from read/build and requires durable device semantics. No boot/trust-chain claims in filesystem APIs.

## Feature boundaries

`read` (container and basic ordinary volumes), `std`, `check`, optional `snapshots`, `compression-zlib`, `compression-lzvn`, `compression-lzfse` and further individually proven types; `build` (fresh construction) later, `mutate` and `transactions` separately qualified, `multi-volume-write`, `clones`, `snapshots-write`, `encryption`, `sealed-read`, `fusion` individually opt-in only once implemented. Some features require read or transaction support. CLI defaults read/std/check only when implemented; no writer enabled by default in early releases. dmgez `apfs-read` / `apfs-build` forward explicitly and never pull future mutable engine or crypto by default. Unsupported flags detected before exposing content as valid; recognize only safe header fields of unsupported profiles. No unknown-required feature flags ignored.

## Success criteria and sequencing

- Independently generated native fixtures from lawful synthetic trees. Compare with native `diskutil`, `newfs_apfs`, `fsck_apfs`, and independent APFS readers, respecting each reference's supported subset. Keep exact OS build, checkpoint, feature flags, input manifest and source digest.
- Reader verifies bounded object checksums, checkpoint validity, object-map resolution at correct XID, B-tree types, filesystem semantics, extents and metadata; incomplete unsupported profile never returns a false success. Safe metadata-only inspection on unsupported variants.
- Fresh constructor only after object/layout/allocator invariants understood. Must pass native filesystem check and mount, then verify contents, resource forks, attributes, symlinks, hard links and multiple-file trees. Output from equivalent manifest deterministic per qualified profile. dmgez may consume sealed sector plan, without implementing APFS itself.
- Mutable operations require copy-on-write transaction and crash-recovery invariants, fault injection at all persistence boundaries, allocator/reference validation, native mount/read/write and snapshots/clones tests. No physical disk repair/recovery goal. Charles uses native VFS/driver integration later; boot and security require independent design and IP review.

## Verification integration

The local `VERIFICATION.md` and `verification/obligations.json` define mandatory profile-specific verification gates in addition to the original acceptance tests. Apply ecosystem standard EVS-1 (copy `shared/VERIFICATION.md` as `docs/architecture/ECOSYSTEM_VERIFICATION.md`). No required proof, model check, native test or critical fault gate can be substituted by coverage or a self-generated round trip. `cargo-nextest`, property tests, fuzz/corpus replay, coverage and deterministic architecture checks are required; formal methods activate at the milestones in the obligation registry.
