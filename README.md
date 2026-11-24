# apfs

An independent Rust implementation of the APFS filesystem.

The initial `apfs-format` crate decodes complete NXSB objects and checkpoint mapping blocks. It verifies Fletcher-64 checksums, validates physical ranges within admitted container geometry, and preserves raw feature masks. It builds without `std` or an allocator.

`apfs-container` scans bounded contiguous checkpoint rings on APFS v2 single-store images. It selects the highest complete transaction after validating descriptor maps, persisted ephemeral objects, and the physical container object-map header. Torn candidates produce rollback diagnostics. Unsupported required features, source failures and exhausted budgets return errors.

Native fixtures from macOS 14.7.2 cover block zero, two checkpoint descriptor pairs, their ephemeral payloads, and both container object-map headers. Apple’s read-only `fsck_apfs` selected XID 2 on the complete source image. [Fixture provenance](tests/fixtures/native-apfs.json)

```sh
cargo nextest run --locked
cargo build --locked -p apfs-container --no-default-features --target aarch64-unknown-none
cargo build --locked -p apfs-container --no-default-features --target x86_64-unknown-none
```

See the [architecture](ARCHITECTURE.md) and [roadmap](ROADMAP.md) for virtual object-map and volume resolution, the filesystem reader, and release qualification.
