# APFS NXSB geometry verification

The [geometry harnesses](kani/geometry.rs) call the production NXSB size and geometry helpers. They check every unsigned 32-bit block-size value and cover all five admitted sizes from 4 KiB through 64 KiB. An independent 128-bit calculation checks admission and both byte endpoints across full-width 64-bit block counts, source lengths, range starts and range lengths. Coverage checks exercise both size admission outcomes, a geometry below the minimum, container-size overflow, admitted geometry, a nonempty range ending at the container boundary, an empty range at that boundary, and block-endpoint overflow.

The [bootstrap tests](../../../container/apfs-container/tests/probe_extent.rs) start from a retained native APFS block. A malformed block size stops after the prefix. A count too large for byte addressing and an incorrect checksum stop after the single bounded bootstrap block. Adding an unknown required bit to the native incompatible feature mask also stops there, with an explicit unsupported-profile result.

Install Kani 0.68.0, run `cargo kani setup`, then run `bash check.sh` from this directory. From the repository root, run `cargo test --locked -p apfs-container --test probe_extent` for the native-derived checks.

On arm64 macOS, Kani 0.68.0 with CBMC 6.11.0 verified both harnesses and reached all 32 cover properties. The seven bootstrap tests passed with Rust 1.99.1.
