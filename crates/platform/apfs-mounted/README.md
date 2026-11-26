# Mounted APFS on macOS

`apfs-mounted` provides typed operations on caller-authorized Darwin descriptors. It can be used as a Cargo path dependency during ExaCopy development. The companion has its own macOS-only dependencies. The portable APFS image crates continue to build for bare-metal targets independently.

| Module | Operations |
|---|---|
| Root | Adopt a directory descriptor, validate byte-preserving entry names, open relative handles, read stored spelling, and create new private directories |
| `volume` and `identity` | Observe mount classification and capability evidence separately. Compare held and named objects using device, real FSID, inode, optional generation, and birth time. |
| `lease` | Acquire, revalidate, and release nonblocking shared or exclusive directory leases |
| `dataless` and `source` | Scope Darwin materialization policy to the current thread. Apply caller admission before the leased data open and perform bounded exact reads and EOF checks from the pinned file. |
| `metadata` | Observe stat attributes, ACL and GUID evidence, xattr names and values, FinderInfo, and fork length evidence. Provision an explicit empty directory ACL and apply and confirm timestamps. |
| `writer` | Exclusively create a private writer, optionally require zero initial flags, sync and check close, and reopen the same file for independent read-back. Seal existing metadata across a full-file barrier or install and verify requested timestamps. |
| `publication` | Observe named entries without payload reads, pin event-only handles, attempt one exclusive relative rename, and query unified identity, extent, change time and bounded metadata after caller-ordered barriers. |
| `recovery` | Reopen an existing private stage read-only under a fresh lease and exact event anchor. Compare recorded identity and extent before data access, then read, probe EOF and query live metadata. |

Use `Directory::from_file` with a directory the caller already authorized. The caller selects the admitted filesystem profile, protects the namespace and ancestry, and controls descriptor inheritance. A directory creation result confirms the requested mode. Apply and confirm the explicit empty ACL before treating it as a private grant. An event-only handle is used for observation. Darwin's open flag alone is insufficient to enforce access restrictions on callers who obtain the descriptor.

Identities and source stamps describe live observations. For a persisted stage, use `ReopenedStage::open_named` to own the component and a fresh event anchor, or pass an existing `publication::pin_entry` anchor to `ReopenedStage::open`. Both forms borrow the stage directory and its lease. Compare all recorded native identity fields and private file policy in the admission callback, which can query bounded ACL evidence through the event anchor. `with_observation` combines live metadata with the revalidated identity and extent on the read-only descriptor. Reads may advance access time. Advisory leases coordinate cooperating writers. Copy grants, intent sequencing, verification digests, publication receipts, and reconciliation policy belong to the operation engine.

Use `publication::OwnedEventEntry::open_named` when an inventory needs to retain the component and its event anchor. It duplicates the held directory descriptor. Use `with_observation` to sample identity, extent, change time and bounded metadata without opening the payload.

The crate's `deny(unsafe_code)` policy permits documented item-level exceptions for Darwin ABI bindings and checked descriptor close. The portable crates retain their workspace prohibition. Run the hosted wrapper suite with `cargo test --locked -p apfs-mounted`.

## ExaCopy integration

From the sibling ExaCopy workspace, use this entry in `[workspace.dependencies]`. Enable it in the consuming crate's macOS dependency table.

```toml
apfs-mounted = { path = "../pomologie/apfs/crates/platform/apfs-mounted", default-features = false }
```

For the strict ExaCopy profile, use `PinnedSource::open_leased` to enforce ownership, mode, links and materialization restrictions before opening data. Keep ExaCopy's transfer and metadata rules in its adapter. Use `InitialFlags::RequireZero` at creation and `BirthTimePolicy::Preserve` at timestamp installation. Darwin can move birth time when installing an earlier modification time. The strict rule reports the change after the timestamp syscall and leaves the stage private for caller reconciliation. The legacy timestamp rule can accept that specific adjustment.

To retain the timestamps already present, finish any required read-back and call `ClosedFile::seal_checked`. Both checks use the same held read-only descriptor. A refusal after the full-file barrier preserves evidence that synchronization succeeded. The private entry is retained on failures.

For an immutable record or pending receipt, `writer::write_private_artifact_checked` performs exclusive creation, scoped metadata admission, bounded writes, a full-file barrier, checked close, and independent exact-byte read-back with an EOF probe. Its returned `ClosedFile` retains the original event anchor for a caller-ordered rename. Use the separate directory barrier to record namespace durability evidence. The caller supplies the bytes, size policy, lease, and any promotion or reconciliation decisions.

For publication, write durable intent in ExaCopy before `attempt_exclusive_rename`. After kernel success, attempt both directory barriers. `RenamedEntry::with_observation` returns the destination's live identity, extent and change time alongside bounded metadata queries on the held inode. It checks the destination and former source before and after the query. `EventEntry::with_observation` uses the same checks on an event-only anchor. Choose `EntrySpelling::Exact` for a private stage and `EntrySpelling::Lookup` when a public spelling alias counts as occupancy. Use `MetadataReadyFile::with_held_metadata` when a separate comparison with the sealed state is needed. ExaCopy still checks lease authority, recorded expectations and its transfer profile. Receipt promotion on a single directory uses one barrier.

The native [publication test](tests/private_publication.rs) exercises the leased source, private stage, independent read-back, strict timestamp rule, and barrier-before-observation sequence on APFS under macOS 14.7.2. Genuine dataless files, native cross-volume substitution, ExaCopy's strict copy-through-receipt profile, process-crash recovery, and hardware power-loss durability remain separate qualification work.

A disposable ExaCopy checkout at `d0b278b` passed the same 105 macOS platform tests with its pinned companion and with this companion plus a local substitution of `observe_mount` for its duplicate volume classification. Fourteen tests were ignored in each normal run. Explicitly running the ignored publication fixture with the substitution stopped at `BasicMetadata(ExtendedAttributes)` during source admission. The result preserves the strict refusal. It leaves the consumer's full adapter migration and strict publication path unqualified.
