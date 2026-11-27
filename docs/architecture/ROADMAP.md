# apfs roadmap

Independent, nonblocking workstream; no APFS functionality required for dmgez 1.0. Each profile test-qualified. Dates are not commitments.

| Version | Scope | Gate |
|---|---|---|
| 0.1.0 | Public spec/fixture ledger, checked object codecs, NXSB, checkpoint detection and inspect | A-CONT-01..02; real native fixtures and malformed tests |
| 0.2.0 | Object maps, B-trees, volume enumeration and exact XID selection | A-CONT-03..04; independent reference and native metadata comparison |
| 0.3.0 | Ordinary file/dir/fork/xattr reads, symlinks/hardlinks, names and basic checking | A-READ-01..02; native content/metadata and bounded parser tests |
| 0.4.0 | Expanded read profiles: compression, snapshots, clone/shared extent observation, multi-volume, additional flags as proven | A-READ-03..04; per-profile gates, never fake unsupported content |
| 0.5.0 | Fresh single-volume data-container constructor, deterministic raw plan and allocation accounting | A-BUILD-01..03; native fsck/mount/read, independent oracle |
| 0.6.0 | Optional dmgez integration and cross-platform packaging profile | Pinned qualified APFS build/read, native DMG attach; no default linkage |
| 0.7.0 | CoW mutation, transaction commit, crash consistency | A-MUT-01; fault injection, native fsck/read/write, no corruption |
| 0.8+ | Multi-volume writes, snapshot/clone lifecycle, advanced allocation | A-MUT-02; reference accounting and persistence qualification |
| Later | Authorized encryption, sealed read, Fusion, system roles, Charles integration | A-MUT-03..04; independent security/IP review, kernel and platform tests |
| 1.0.0 | Stable supported profile API, release evidence and security docs | Advertised features all pass; advanced optional profiles can remain absent |

Start by collecting lawful synthetic APFS fixtures across Sequoia-era and selected modern OS versions. Document format evidence gaps, not assume current layout from 2020 reference. Maintain exact unsupported flags and check native behavior. Read-only parser first, then independent writer only with allocator/checkpoint qualification. No public claim of writable support without real crash and fsck evidence. Do not block dmgez or hfsplus releases on APFS research. Package names checked before registry publication.

## v0.1.0 source packages

The dependency order from the normalized Cargo manifests is `libapfs-core`, `apfs-format`, and `apfs-mounted` first, then `apfs-container`, then `apfs-reader`. The foundation crate imports as `apfs_core` in Rust. The five exact package names returned 404 from `cargo owner --list` during the candidate check.

At `5d1dde5`, Cargo 1.99.1 assembled all five archives. Its built-in workspace verifier stopped on a missing checksum for an unpublished sibling. Running the locked package assembly with `--no-verify` and testing the extracted archives in a fresh offline workspace passed 215 tests. Each archive's recorded Git commit and included license files were checked. Package checksums, test output, and the dependency order are in `target/release-candidates/v0.1.0/5d1dde5-cargo/`. The acceptance and obligation gates apply separately from package assembly.

At `a2f8d72`, Cargo 1.99.1 assembled all five archives again. An offline workspace used only the extracted sibling packages and ran the locked all-features test suite with Rust and Cargo 1.98.0 on arm64 macOS. It passed 219 tests. Each archive contained its license and recorded the expected Git revision. The archives, workspace lock, transcripts, and checksums are in `target/release-candidates/v0.1.0/a2f8d72-cargo/`. The verification record SHA-256 is `14bc43e81217d8318fe60b28f5964d8679c690d5c1ca2b80dd708ac6d51b5f5f`.

The five archives from `7aa343c` passed the same extracted all-features check on Rust 1.98.0 with all 220 tests passing. The extracted workspace retained all 24 registry package pins from the source lockfile. The artifacts and transcripts are in `target/release-candidates/v0.1.0/7aa343c-cargo/`. The verification record SHA-256 is `9cb11e956bcf2de1519ef2f2df390164b6b84f63fe244d179ce22c10b544ef7f`.

The five archives from `28c3a8a` passed 228 tests after extraction on Rust 1.98.0, with all 24 registry package pins preserved. The evidence and archives are in `target/release-candidates/v0.1.0/28c3a8a-cargo/`. The verification record SHA-256 is `c196ae59681a4d0396fb4284e4e769f3675a2e19e7cef9dc26eeb4bc004b70aa`.

The five archives from `8878ed1`, ExaCopy's mounted source pin, passed all 229 tests after extraction on arm64 macOS with Rust 1.98.0 and all 24 registry pins preserved. The suite included the mounted regressions for bounded xattr inventory and resource-fork absence. The `apfs-mounted` archive SHA-256 is `2f29d1bd40efe8c4b1064f7111f20d654e92163569d89d377f17bc8705b2a503`. The verification record is in `target/release-candidates/v0.1.0/8878ed1-cargo/` with SHA-256 `61941499415129f10a3384a533b822cabad88551f5adeb377bf1260e032ad954`. Consumer integration and native qualification have separate evidence. [Mounted integration status](../features/MOUNTED.md)

## Verification integration

The local `VERIFICATION.md` and `verification/obligations.json` define mandatory profile-specific verification gates in addition to the original acceptance tests. Apply ecosystem standard EVS-1 (copy `shared/VERIFICATION.md` as `docs/architecture/ECOSYSTEM_VERIFICATION.md`). No required proof, model check, native test or critical fault gate can be substituted by coverage or a self-generated round trip. `cargo-nextest`, property tests, fuzz/corpus replay, coverage and deterministic architecture checks are required; formal methods activate at the milestones in the obligation registry.

## Cross-cutting release gate: A-PORT-01
Beginning at 0.1.0, every newly introduced kernel-facing crate must pass EES-1 §3a on both provisional bare-metal targets and preserve hosted semantic parity. Apply incrementally to later reader/writer/transaction features; std is allowed in standalone bulk builders and adapters. Actual Charles driver qualification remains a later milestone.
