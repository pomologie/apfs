# Unicode 9 name tables

These generated tables describe the Unicode 9.0.0 repertoire used by the APFS reader's versioned name comparison. The tables include private-use code points assigned an age in Unicode 9. Unassigned points, surrogates and noncharacters are excluded. The canonical decomposition table excludes compatibility mappings. The reader handles Hangul syllable decomposition algorithmically. The default full folding table includes `C` and `F` entries, with `S` and Turkic `T` entries omitted. [Unicode 9.0.0 release](https://www.unicode.org/versions/Unicode9.0.0/)

The Unicode Consortium maintains the source data in `unicodetools` at revision `725fb6055cd42915c74bcf77b91aa8fb8ef18669`. The generator verifies each input's SHA-256 before reading its records. [Pinned Unicode data directory](https://github.com/unicode-org/unicodetools/tree/725fb6055cd42915c74bcf77b91aa8fb8ef18669/unicodetools/data/ucd/9.0.0-Update) [Unicode data license](UNICODE-LICENSE)

| Input | SHA-256 |
| --- | --- |
| `CaseFolding.txt` | `37d40cf8c2c35637f4a04e746814e1fc4eb764c272bed9238a87ee96a4866857` |
| `DerivedAge.txt` | `5cb15b04693c43df16e0d304deca049e93b001445d163184e0ff1b7c8c852146` |
| `UnicodeData.txt` | `68dfc414d28257b9b5d6ddbb8b466c768c00ebdf6cbf7784364a9b6cad55ee8f` |

Place the three inputs in one directory under their original filenames. From the APFS checkout, run the generator and its byte-for-byte check.

```sh
python3 -B crates/filesystem/apfs-reader/src/names/data/generate.py /path/to/ucd-9
python3 -B crates/filesystem/apfs-reader/src/names/data/generate.py /path/to/ucd-9 --check
```

All integers use little-endian encoding. Records have fixed widths, lack inter-record padding, and sort by their first field. Age intervals include both endpoints. In the mapping records, unused trailing slots contain zero.

| Output | Record layout | Records | SHA-256 |
| --- | --- | ---: | --- |
| `age.bin` | `u32` first, `u32` last | 638 | `84c7734ba823c48c154646787f4d1f07e54a6ef7d8477a8010111f6d4d142cd6` |
| `combining.bin` | `u32` scalar, `u8` nonzero canonical combining class | 814 | `7013c16b3465a572eed33a9b09d1e400daf0363c34da4a22111292ca8c09ff43` |
| `decomposition.bin` | `u32` scalar, `[u32; 3]` direct canonical mapping slots | 2,060 | `287a1b579b5db2504282df9b11e491025baf6172d1def042e5240c38b0b4479b` |
| `casefold.bin` | `u32` scalar, `[u32; 3]` full fold mapping slots | 1,401 | `8562246a5850414d83819f79bfa5f2dcaadf17539e6c3b71223ef86752345341` |
