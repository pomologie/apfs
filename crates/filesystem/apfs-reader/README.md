# APFS filesystem reader

`VolumeView` opens an explicitly selected ordinary volume using its checkpoint-bound volume object map. It checks the root inode, reads inode metadata and declared data-stream sizes, pages through directory records in on-disk order, and looks up names by their stored UTF-8 bytes. Exact lookup also checks the target inode. Directory paging checks the declared child count and uses a cursor scoped to the container, volume, checkpoint, and directory. Each page scans the matching directory records under traversal and aggregate object-read budgets.

The admitted virtual filesystem tree uses variable-sized key/value slots and standard checksummed object headers in an ordinary unencrypted volume. Traversal checks object identity and storage, occupied slot bounds and overlap, inode/type ordering, split-child routing, and repeated references in the visited nodes. Filesystem-node free-list head locations are checked for bounds. [Apple File System Reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf)

`open_file` admits a regular file with continuous logical extents and an unshared data stream. Every data range must map to owning, checksummed records from the selected physical extent-reference tree and avoid the known checkpoint and volume metadata blocks. `FileData::read_exact_at` reads within the logical file length. Metadata and payload reads share the volume budget. `read_link` returns the bytes of an inline symbolic-link target. Sparse, cloned or shared, compressed, and encrypted data states return typed unsupported errors. Resource-fork and general xattr access, filesystem Unicode equivalence, hashed-node verification, and whole-volume consistency checking remain future profiles.

The hosted tests exercise directory, inode, and ordinary file data as part of A-READ-01 and A-READ-02. Apple’s read-only checker selected XID 4 on the populated images and XID 6 on the fragmented image. The split tree contains 88 files across nine leaves. The payload fixtures validate a 19,000-byte native file, data from both leaves of the physical extent-reference tree, an empty file, and a symbolic link. The fragmented fixture verifies a file with four nonadjacent physical extents, including unaligned reads across every extent boundary. The provenance files record the synthetic inputs and exact native block slices. [Populated tree](tests/fixtures/sonoma-populated-fsroot.json) · [Split tree](tests/fixtures/sonoma-split-metadata.json) · [Payloads](tests/fixtures/sonoma-payload-blocks.json) · [Fragmented file](tests/fixtures/sonoma-fragmented-blocks.json)

```sh
cargo nextest run --locked -p apfs-reader --no-default-features
cargo build --locked -p apfs-reader --no-default-features --target aarch64-unknown-none
cargo build --locked -p apfs-reader --no-default-features --target x86_64-unknown-none
```
