# Mounted APFS on macOS

`apfs-mounted` provides typed operations on caller-authorized Darwin descriptors. It can be used as a Cargo path dependency during ExaCopy development. The companion has its own macOS-only dependencies. The portable APFS image crates continue to build for bare-metal targets independently.

| Module | Operations |
|---|---|
| Root | Adopt a directory descriptor, validate byte-preserving entry names, open relative handles, read stored spelling, and create new private directories |
| `volume` and `identity` | Observe filesystem type and capability evidence, compare held and named objects using device, real FSID, inode, optional generation, and birth time |
| `lease` | Acquire, revalidate, and release nonblocking shared or exclusive directory leases |
| `dataless` and `source` | Scope Darwin materialization policy to the current thread and perform bounded exact reads from a pinned regular file |
| `metadata` | Observe stat attributes, ACL and GUID evidence, xattr names and values, FinderInfo, and fork length evidence. Provision an explicit empty directory ACL and apply and confirm timestamps. |
| `writer` | Create a private writer, check positioned progress, issue full-file and directory barriers, check consuming close, and reopen the same file for independent readback |
| `publication` | Observe named entries without payload reads, pin event-only handles, attempt exclusive relative rename, and report namespace evidence and each directory barrier |

Use `Directory::from_file` with a directory the caller already authorized. The caller selects the admitted filesystem profile, protects the namespace and ancestry, and controls descriptor inheritance. A directory creation result confirms the requested mode. Apply and confirm the explicit empty ACL before treating it as a private grant. An event-only handle is used for observation. Darwin's open flag alone is insufficient to enforce access restrictions on callers who obtain the descriptor.

Identities and source stamps describe live observations. Reopen and validate a fresh handle when recovering from a persisted record. Advisory leases coordinate cooperating writers. Copy grants, intent sequencing, verification digests, publication receipts, and reconciliation policy belong to the operation engine.

The crate's `deny(unsafe_code)` policy permits documented item-level exceptions for Darwin ABI bindings and checked descriptor close. The portable crates retain their workspace prohibition. Run the hosted wrapper suite with `cargo test --locked -p apfs-mounted`.

## ExaCopy integration

From the sibling ExaCopy workspace, use this entry in `[workspace.dependencies]`. Enable it in the consuming crate's macOS dependency table.

```toml
apfs-mounted = { path = "../pomologie/apfs/crates/platform/apfs-mounted", default-features = false }
```

The native [publication test](tests/private_publication.rs) ran on APFS under macOS 14.7.2. It reads from a pinned source, creates a leased private stage, checks the full-file barrier and close, independently reads the payload back, applies timestamps, and checks the held identity through exclusive publication and both directory barriers. Applying an earlier modification time can also move APFS birth time. Use the live identity returned by the metadata-ready stage for publication and subsequent records.

A disposable ExaCopy checkout at `0a6b020` exercised the held identity, volume capability, and dataless policy adapters on macOS with Rust 1.100. Its metadata and journal encodings stayed at their existing boundary, and all 53 signed Darwin journal tests passed. The strict copy-through-receipt fixture still stops at extended-attribute admission. Full adapter migration, genuine dataless files, native cross-volume substitution, and crash and power-loss qualification remain open.
