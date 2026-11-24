# APFS filesystem metadata reader

`VolumeView` opens an explicitly selected ordinary volume using its checkpoint-bound volume object map. It checks the root inode, reads inode metadata and declared data-stream sizes, pages through directory records in on-disk order, and looks up names by their stored UTF-8 bytes. Exact lookup also checks the target inode. Directory paging checks the declared child count and uses a cursor scoped to the container, volume, checkpoint, and directory. Each page scans the matching directory records under traversal and aggregate object-read budgets.

The admitted virtual filesystem tree uses variable-sized key/value slots and standard checksummed object headers in an ordinary unencrypted volume. Traversal checks object identity and storage, occupied slot bounds and overlap, inode/type ordering, split-child routing, and repeated references in the visited nodes. Filesystem-node free-list head locations are checked for bounds. The reader exposes file kinds and stream sizes as metadata. Payload reads, symlink target reads, xattr access, filesystem Unicode equivalence, hashed-node verification, and whole-volume consistency checking remain future profiles. [Apple File System Reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf)

The hosted tests exercise the metadata portion of A-READ-01 using native empty, populated, and split trees. Apple’s read-only checker selected XID 4 on both populated images. The split tree contains 88 files across nine leaves. The provenance files record the native inputs and exact metadata block slices. [Populated tree](tests/fixtures/sonoma-populated-fsroot.json) · [Split tree](tests/fixtures/sonoma-split-metadata.json)

```sh
cargo nextest run --locked -p apfs-reader --no-default-features
cargo build --locked -p apfs-reader --no-default-features --target aarch64-unknown-none
cargo build --locked -p apfs-reader --no-default-features --target x86_64-unknown-none
```
