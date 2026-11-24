# APFS container verification

The [object-map harness](kani/object_map.rs) covers the leaf selection portion of A-V03. It calls the production inclusive predecessor search and leaf visibility filter. The input is a prefix of at most eight strictly ordered unique keys. OIDs and transaction IDs use the full unsigned 64-bit range, and each leaf value can be live or deleted. An independent linear model filters by OID and requested XID, chooses the greatest eligible XID, and applies its tombstone.

The harness checks an empty leaf, a full eight-key leaf with future mappings, a query with only future versions, a tombstone over an older live version, and equality at the maximum XID. Sorting and uniqueness are prior format admission checks. Tree routing, physical address admission, object namespace validation, and consistency of a historical checkpoint or snapshot remain separate obligations. See the [repository obligation registry](../../../../verification/obligations.json).

Install Kani 0.68.0 and run `cargo kani setup`, then run `bash check.sh` from this directory.

For the negative witness, use a disposable checkout and change the search predicate from `key_at(middle)? <= key` to `key_at(middle)?.id <= key.id`. The altered search ignores the XID among versions of one OID. The live-mapping equivalence check must fail.
