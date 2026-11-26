# Mounted APFS on macOS

`apfs-mounted` provides typed operations on caller-authorized Darwin descriptors. It can be used as a Cargo path dependency during ExaCopy development. The companion has its own macOS-only dependencies. The portable APFS image crates continue to build for bare-metal targets independently.

| Module | Operations |
|---|---|
| Root | Adopt a directory descriptor, validate byte-preserving entry names, open relative handles, read stored spelling, and create new private directories |
| `volume` and `identity` | Observe mount classification and capability evidence separately. Compare held and named objects using device, real FSID, inode, optional generation, and birth time. |
| `lease` | Acquire, revalidate, and release nonblocking shared or exclusive directory leases |
| `dataless` and `source` | Scope Darwin materialization policy to the current thread. Apply caller admission before the leased data open and perform bounded exact reads and EOF checks from the pinned file. |
| `metadata` | Observe stat attributes, ACL and GUID evidence, xattr names and values, FinderInfo, and fork length evidence. Provision an explicit empty directory ACL and apply and confirm timestamps. |
| `writer` | Exclusively create a private writer, optionally require zero initial flags, sync and check close, and reopen the same file for independent read-back. Run metadata checks across timestamp updates and file barriers. |
| `publication` | Observe named entries without payload reads, pin event-only handles, attempt one exclusive relative rename, and sample namespace evidence after caller-ordered barriers. |

Use `Directory::from_file` with a directory the caller already authorized. The caller selects the admitted filesystem profile, protects the namespace and ancestry, and controls descriptor inheritance. A directory creation result confirms the requested mode. Apply and confirm the explicit empty ACL before treating it as a private grant. An event-only handle is used for observation. Darwin's open flag alone is insufficient to enforce access restrictions on callers who obtain the descriptor.

Identities and source stamps describe live observations. Reopen and validate a fresh handle when recovering from a persisted record. Advisory leases coordinate cooperating writers. Copy grants, intent sequencing, verification digests, publication receipts, and reconciliation policy belong to the operation engine.

The crate's `deny(unsafe_code)` policy permits documented item-level exceptions for Darwin ABI bindings and checked descriptor close. The portable crates retain their workspace prohibition. Run the hosted wrapper suite with `cargo test --locked -p apfs-mounted`.

## ExaCopy integration

From the sibling ExaCopy workspace, use this entry in `[workspace.dependencies]`. Enable it in the consuming crate's macOS dependency table.

```toml
apfs-mounted = { path = "../pomologie/apfs/crates/platform/apfs-mounted", default-features = false }
```

For the strict ExaCopy profile, use `PinnedSource::open_leased` to enforce ownership, mode, links and materialization restrictions before opening data. Keep ExaCopy's transfer and metadata rules in its adapter. Use `InitialFlags::RequireZero` at creation and `BirthTimePolicy::Preserve` at timestamp installation. Darwin can move birth time when installing an earlier modification time. The strict rule reports the change after the timestamp syscall and leaves the stage private for caller reconciliation. The legacy timestamp rule can accept that specific adjustment.

For publication, write durable intent in ExaCopy before `attempt_exclusive_rename`. After kernel success, attempt both directory barriers and sample `RenamedEntry::observe`. ExaCopy can then check lease and metadata requirements in the same post-barrier phase. Receipt promotion on a single directory uses one barrier. Keep all results for reconciliation after uncertainty.

The native [publication test](tests/private_publication.rs) exercises the leased source, private stage, independent read-back, strict timestamp rule, and barrier-before-observation sequence on APFS under macOS 14.7.2. Genuine dataless files, native cross-volume substitution, ExaCopy's strict copy-through-receipt profile, process-crash recovery, and hardware power-loss durability remain separate qualification work.

A disposable ExaCopy checkout at `d0b278b` passed the same 105 macOS platform tests with its pinned companion and with this companion plus a local substitution of `observe_mount` for its duplicate volume classification. Fourteen tests were ignored in each normal run. Explicitly running the ignored publication fixture with the substitution stopped at `BasicMetadata(ExtendedAttributes)` during source admission. The result preserves the strict refusal. It leaves the consumer's full adapter migration and strict publication path unqualified.
