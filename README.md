# apfs

An independent Rust implementation of the APFS filesystem.

The initial `apfs-format` crate decodes complete NXSB objects and checkpoint mapping blocks. It verifies Fletcher-64 checksums, validates physical ranges within admitted container geometry, and preserves raw feature masks. It builds without `std` or an allocator.

`apfs-container` scans bounded contiguous checkpoint rings on APFS v2 single-store images. It selects the highest complete transaction after validating descriptor maps, persisted ephemeral objects, and the physical container object-map header. Torn candidates produce rollback diagnostics. Unsupported required features, source failures and exhausted budgets return errors.

The selected view resolves container-namespace mappings through a bounded, physical, fixed-record object-map tree. Checked reads validate the mapped object's checksum, identifier, transaction and expected virtual type. Lookup handles visible tombstones and returns errors for unsupported maps, including maps that require encryption or snapshot processing. The current profile and evidence are in the [container specification](docs/features/CONTAINER.md).

Native fixtures from macOS 14.7.2 cover two checkpoints, their ephemeral payloads, both container object maps, and the volume superblock resolved by the second map. Apple’s read-only `fsck_apfs` selected XID 2 on the complete source image and reported the same volume UUID. [Fixture provenance](tests/fixtures/native-apfs.json)

```sh
cargo nextest run --locked
cargo build --locked -p apfs-container --no-default-features --target aarch64-unknown-none
cargo build --locked -p apfs-container --no-default-features --target x86_64-unknown-none
```

See the [architecture](ARCHITECTURE.md) and [roadmap](ROADMAP.md) for volume validation and volume-specific object maps, the filesystem reader, and release qualification.
