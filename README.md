# apfs

An independent Rust implementation of the APFS filesystem.

The initial `apfs-format` crate decodes complete NXSB objects and checkpoint mapping blocks. It verifies Fletcher-64 checksums, validates physical ranges within admitted container geometry, and preserves raw feature masks. It builds without `std` or an allocator.

Native fixtures from macOS 14.7.2 cover the block-zero superblock and two checkpoint descriptor pairs. [Fixture provenance](tests/fixtures/native-apfs.json)

```sh
cargo nextest run --locked
cargo build --locked -p apfs-format --no-default-features --target aarch64-unknown-none
cargo build --locked -p apfs-format --no-default-features --target x86_64-unknown-none
```

See the [architecture](ARCHITECTURE.md) and [roadmap](ROADMAP.md) for checkpoint selection, object-map resolution, and the filesystem reader.
