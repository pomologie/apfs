"""Exercise APFS profile and release evidence checks in disposable repositories."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from uuid import UUID

from check_release_evidence import (
    EvidenceError, POLICY_PATH, REGISTRY_PATH, archive_hash, required_matrix, validate,
    verify_native_geometry_policy, verify_native_window_policy,
)
from apfs_evidence_transcript import (
    verify_checkpoint_differential, verify_checkpoint_layouts, verify_checkpoint_model,
    verify_locator_properties, verify_native_checkpoints, verify_native_extent, verify_native_full_open,
    verify_native_size_matrix,
    verify_complete_objects, verify_format_fuzz, verify_native_geometry,
    verify_native_windows,
    verify_span_properties,
)


PROFILE = "format-kani"
HARNESS = "object::verification::sample"
TRANSCRIPT = f"""Kani Rust Verifier 0.68.0 (cargo plugin)
CBMC 6.11.0
Checking harness {HARNESS}...
 ** 0 of 5 failed (1 unreachable)
 ** 2 of 2 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Manual Harness Summary:
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
"""
TLC_PROFILE = "checkpoint-tlc"
TLC_MODEL = "CheckpointSelection"
TLC_RUNTIME = f"""TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)
Running breadth-first search Model-Checking with fp 0 and seed 0 with 1 worker on 8 cores (Java 21.0.8 aarch64).
Semantic processing of module {TLC_MODEL}
"""
TLC_TRANSCRIPT = f"""APFS TLC baseline
{TLC_RUNTIME}Finished computing initial states: 3200 distinct states generated at 2026-11-26.
Checking temporal properties for the complete state space with 13196 total distinct states at (2026-11-26)
Finished checking temporal properties in 00s at 2026-11-26
Model checking completed. No error has been found.
16396 states generated, 13196 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 6.
APFS TLC negative witness
{TLC_RUNTIME}Error: Invariant SelectionMatchesEvidence is violated.
Error: The behavior up to this point is:
State 1: <Initial predicate>
APFS TLC witness exit code: 12
"""
CHECKSUM_PROFILE = "format-checksum-differential"
CHECKSUM_TRANSCRIPT = """rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS checksum native native-block-0.bin 4096 46653a58ffa467b1
APFS checksum uniform 4096 0
APFS checksum singleton 4096 0 8 305419896
APFS checksum singleton 4096 0 2048 305419896
APFS checksum singleton 4096 0 4092 305419896
APFS checksum differential completed
"""
BOOTSTRAP_PROFILE = "bootstrap-properties"
BOOTSTRAP_TRANSCRIPT = """rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS bootstrap property size-prefix 5 7
APFS bootstrap property geometry 4096 7 3 24
APFS bootstrap property checksum-window 65 9
APFS bootstrap property required-feature 63
APFS bootstrap property typed-required-feature 4034 16136
APFS bootstrap property mixed-feature-cutoff 4096 32
APFS bootstrap property geometry-cutoff 4096 4 12
APFS bootstrap property candidate-feature-cutoff 8 2 11
APFS bootstrap properties completed
"""
NATIVE_PROFILE = "bootstrap-native"
NATIVE_FIXTURE = {
    "os_version": "14.7.2", "os_build": "23H311", "architecture": "arm64", "oracle_version": "2236.141.1",
    "checkpoint_xid": 4, "wire_checksum": "dd9368444871caee", "ledger_sha256": "a" * 64, "raw_sha256": "b" * 64,
    "metadata_sha256": "c" * 64, "bootstrap_sha256": "d" * 64, "fsroot_sha256": "e" * 64,
}
NATIVE_TRANSCRIPT = f"""rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS native bootstrap ledger {'a' * 64}
APFS native bootstrap oracle 14.7.2 23H311 arm64 2236.141.1 0 4 {'b' * 64}
APFS native bootstrap fixture {'c' * 64} {'d' * 64} {'e' * 64}
APFS native bootstrap admitted 67108864 4096 16384 4 dd9368444871caee 2
APFS native bootstrap refused count 2
APFS native bootstrap refused type 2
APFS native bootstrap refused checksum 2
APFS native bootstrap refused size 1
APFS native bootstrap refused required-feature 2
APFS native bootstrap replay completed
"""


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="apfs-release-evidence-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve() / "candidate"
        self.root.mkdir()
        self.bundle = self.root.with_name("bundle.json")
        self.log = self.root.with_name("kani.log")
        profile = {
            "obligation": "A-V01", "method": "kani", "features": [],
            "command": ["bash", "crates/formats/apfs-format/verification/check.sh"],
            "tool_versions": {"kani": "0.68.0", "cbmc": "6.11.0"}, "bounds": {"scalar_bits": 64},
            "harnesses": {HARNESS: 2},
        }
        self.policy = {"schema_version": 1, "milestone": "0.1.0", "profiles": {PROFILE: profile}}
        self.registry = {"project": "apfs", "methods": {"kani": "proof", "native": "native"}, "obligations": [{
            "id": "A-V01", "activation": "0.1.0", "mandatory_when_activated": True,
            "required_methods": ["kani"],
        }]}
        self.git("init", "--quiet")
        self.commit_policy()
        self.record = {
            "schema_version": 1, "obligation_id": "A-V01", "profile": PROFILE, "method": "kani",
            "status": "pass", "commit": self.commit, "dirty": False, "source_hash": self.digest,
            "features": [], "tool_versions": profile["tool_versions"], "command": profile["command"],
            "assumptions": [], "bounds": profile["bounds"], "artifacts": [], "duration_ms": 1,
            "runner": {"os": "macos", "arch": "aarch64"}, "exit_code": 0, "proof": {"theorem": PROFILE},
        }
        self.set_transcript(TRANSCRIPT)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", self.root, *args], text=True).strip()

    def commit_policy(self):
        (self.root / "verification").mkdir(exist_ok=True)
        (self.root / POLICY_PATH).write_text(json.dumps(self.policy), encoding="utf-8")
        (self.root / REGISTRY_PATH).write_text(json.dumps(self.registry), encoding="utf-8")
        self.git("add", "verification")
        self.git("-c", "user.name=APFS test", "-c", "user.email=apfs-test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture policy")
        self.commit = self.git("rev-parse", "HEAD")
        self.digest = archive_hash(self.root, self.commit)

    def set_transcript(self, value):
        self.log.write_text(value, encoding="utf-8")
        self.record["artifacts"] = [{
            "name": "transcript", "uri": self.log.name, "sha256": hashlib.sha256(value.encode()).hexdigest(),
        }]

    def check(self, records, requested_profile=None):
        self.bundle.write_text(json.dumps(records), encoding="utf-8")
        return validate(self.root, self.bundle, requested_profile)

    def set_tlc_profile(self):
        profile = {
            "obligation": "A-V02", "method": "tlc", "features": [],
            "command": ["bash", "crates/container/apfs-container/verification/models/check-evidence.sh"],
            "tool_versions": {"tlc": "2.19", "java": "21.0.8"},
            "bounds": {"candidate_xids": 3, "ring_slots": 2, "workers": 1, "seed": 0, "fingerprint_index": 0},
            "model": {"name": TLC_MODEL, "initial_states": 3200, "states": 16396, "distinct_states": 13196,
                      "depth": 6, "violated_invariant": "SelectionMatchesEvidence"},
        }
        self.policy["profiles"][TLC_PROFILE] = profile
        self.registry["methods"]["tlc"] = "bounded model"
        self.registry["obligations"].append({
            "id": "A-V02", "activation": "0.1.0", "mandatory_when_activated": True, "required_methods": ["tlc"],
        })
        self.commit_policy()
        self.record.update(
            commit=self.commit, source_hash=self.digest, profile=TLC_PROFILE, obligation_id=profile["obligation"],
            method="tlc", command=profile["command"], tool_versions=profile["tool_versions"], bounds=profile["bounds"],
            seed="0", proof={"theorem": TLC_PROFILE, "states": 16396, "distinct_states": 13196},
        )
        self.set_transcript(TLC_TRANSCRIPT)

    def set_checksum_profile(self):
        profile = {
            "obligation": "A-V01", "method": "differential", "partial": True, "features": [],
            "command": ["bash", "crates/formats/apfs-format/verification/check-checksum.sh"],
            "tool_versions": {"rustc": "1.99.1"},
            "bounds": {"fixture_bytes": 4096, "max_block_bytes": 4096, "distinct_word": 305419896},
            "checksum_cases": {"fixtures": {"native-block-0.bin": "46653a58ffa467b1"},
                               "block_sizes": [4096], "uniform_words": [0]},
        }
        self.policy["profiles"][CHECKSUM_PROFILE] = profile
        self.registry["methods"]["differential"] = "independent comparison"
        self.registry["obligations"][0]["required_methods"].append("differential")
        self.commit_policy()
        self.record.update(
            commit=self.commit, source_hash=self.digest, profile=CHECKSUM_PROFILE, method="differential",
            command=profile["command"], tool_versions=profile["tool_versions"], bounds=profile["bounds"],
        )
        del self.record["proof"]
        self.set_transcript(CHECKSUM_TRANSCRIPT)

    def set_bootstrap_profile(self):
        profile = {
            "obligation": "A-V01", "method": "property", "partial": True, "features": [],
            "command": ["bash", "crates/container/apfs-container/verification/check-bootstrap-properties.sh"],
            "tool_versions": {"rustc": "1.99.1"},
            "bounds": {"size_bits": 32, "geometry_bits": 64, "max_header_prefix_bytes": 64,
                       "incompatible_feature_bits": 64},
            "property_cases": {"size-prefix": [[5, 7]], "geometry": [[4096, 7, 3, 24]],
                               "checksum-window": [[65, 9]], "required-feature": [[63]],
                               "typed-required-feature": [[4034, 16136]], "mixed-feature-cutoff": [[4096, 32]],
                               "geometry-cutoff": [[4096, 4, 12]], "candidate-feature-cutoff": [[8, 2, 11]]},
        }
        self.policy["profiles"][BOOTSTRAP_PROFILE] = profile
        self.registry["methods"]["property"] = "property test"
        self.registry["obligations"][0]["required_methods"].append("property")
        self.commit_policy()
        self.record.update(
            commit=self.commit, source_hash=self.digest, profile=BOOTSTRAP_PROFILE, method="property",
            command=profile["command"], tool_versions=profile["tool_versions"], bounds=profile["bounds"],
        )
        del self.record["proof"]
        self.set_transcript(BOOTSTRAP_TRANSCRIPT)

    def set_native_profile(self):
        profile = {
            "obligation": "A-V01", "method": "native", "partial": True, "features": [],
            "command": ["bash", "crates/filesystem/apfs-reader/verification/check-native-bootstrap.sh"],
            "tool_versions": {"rustc": "1.99.1"},
            "bounds": {"block_bytes": 4096, "block_count": 16384, "admitted_reads": 2,
                       "refused_reads": {"size": 1, "count": 2, "type": 2, "checksum": 2, "required-feature": 2}},
            "native_fixture": deepcopy(NATIVE_FIXTURE),
        }
        self.policy["profiles"][NATIVE_PROFILE] = profile
        self.registry["obligations"][0]["required_methods"].append("native")
        self.commit_policy()
        self.record.update(commit=self.commit, source_hash=self.digest, profile=NATIVE_PROFILE, method="native",
                           command=profile["command"], tool_versions=profile["tool_versions"], bounds=profile["bounds"],
                           fixture_hash=NATIVE_FIXTURE["ledger_sha256"])
        del self.record["proof"]
        self.set_transcript(NATIVE_TRANSCRIPT)

    def test_fresh_full_open_matches_each_runs_oracle_and_image_digest(self):
        provenance = {"macos": "14.7.2", "macos_build": "23H311", "arch": "arm64",
                      "runner_sha256": "a" * 64, "harness_sha256": "b" * 64}
        bounds = {"image_bytes": 134217728, "block_sizes": [4096, 8192]}
        versions = {"rustc": "1.99.1", "apple_format": "2236.141.1"}
        rows = []
        for index, size in enumerate(bounds["block_sizes"], 1):
            uuid = UUID(int=index)
            label = f"Pomologie {size}"
            count = bounds["image_bytes"] // size
            digest = hashlib.sha256(str(size).encode("ascii")).hexdigest()
            rows.append({
                "block_bytes": size, "block_count": count, "xid": 2, "descriptor": 4, "descriptor_ring_slots": 8,
                "descriptor_ring_index": 2, "descriptor_ring_length": 2, "descriptor_ring_next": 4, "mapping_count": 4,
                "volume_uuid": uuid.hex, "volume_label": label, "raw_sha256": digest, "raw_sha256_after": digest,
                "raw_unchanged": True, "formatter": ["/sbin/newfs_apfs", "-b", str(size), "-v", label, "$scratch/checkpoint.raw"],
                "checker": ["/sbin/fsck_apfs", "-n", "$scratch/checkpoint.raw"], "formatter_log": "completed",
                "checker_log": (f"Checking the checkpoint with transaction ID 2.\n"
                                f"The volume {label} was formatted by newfs_apfs (2236.141.1)\n"
                                f"The volume sample with UUID {str(uuid).upper()} appears to be OK.\n"
                                "** The container sample appears to be OK.\n"),
                "rust_log": f"checkpoint {size} {count} 2 4 8 2 2 4 4\nvolume {uuid.hex} {label}\n",
            })
        report = provenance | {"build_log": "Compiled $scratch", "rust": "rustc 1.99.1 (pinned)",
                               "image_bytes": bounds["image_bytes"], "results": rows}
        verify_native_full_open(report, provenance, bounds, versions)
        for field, value, expected in (
            ("raw_sha256_after", "0" * 64, "digests differ"),
            ("volume_uuid", rows[0]["volume_uuid"], "volume identities differ"),
            ("checker", ["/sbin/fsck_apfs", "$scratch/checkpoint.raw"], "acquisition command"),
            ("formatter_log", "/private/tmp/test/checkpoint.raw", "temporary paths"),
            ("rust_log", rows[0]["rust_log"], "Rust full-open transcript"),
        ):
            altered = report | {"results": [rows[0], rows[1] | {field: value}]}
            with self.subTest(field=field), self.assertRaisesRegex(EvidenceError, expected):
                verify_native_full_open(altered, provenance, bounds, versions)
        with self.assertRaisesRegex(EvidenceError, "incomplete native full-open matrix"):
            verify_native_full_open(report | {"results": rows[:1]}, provenance, bounds, versions)

    def test_native_size_matrix_requires_each_size_and_both_read_patterns(self):
        fixture = {"ledger_sha256": "a" * 64, "host": ["14.7.2", "23H311", "arm64"], "checksums": {
            "4096": "ff6b7d4b7fef6594", "8192": "93dfe781b706a414",
        }}
        bounds = {"extent_bytes": 134217728, "prefix_bytes": 40, "trailing_bytes": 1024}
        versions = {"rustc": "1.99.1"}
        padded = "APFS native bootstrap matrix probe 8192 134218752 134217728 0 40 0 8192\n"
        transcript = f"""rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS native bootstrap matrix 4096 32768 134217728 ff6b7d4b7fef6594
APFS native bootstrap matrix probe 4096 134217728 134217728 0 40 0 4096
APFS native bootstrap matrix probe 4096 134218752 134217728 0 40 0 4096
APFS native bootstrap matrix 8192 16384 134217728 93dfe781b706a414
APFS native bootstrap matrix probe 8192 134217728 134217728 0 40 0 8192
{padded}APFS native bootstrap matrix ledger {fixture['ledger_sha256']}
APFS native bootstrap matrix oracle 14.7.2 23H311 arm64
APFS native bootstrap matrix completed
"""
        verify_native_size_matrix(transcript, fixture, bounds, versions)
        for old, replacement in ((padded, ""), ("93dfe781b706a414", "4bcc7609f30e3ca2"),
                                 ("0 40 0 8192", "0 40 0 4096"), (fixture["ledger_sha256"], "b" * 64)):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, "probe rows"):
                verify_native_size_matrix(transcript.replace(old, replacement), fixture, bounds, versions)

    def test_native_extent_requires_both_source_lengths_and_exact_reads(self):
        fixture = {key: value for key, value in NATIVE_FIXTURE.items()
                   if key not in {"metadata_sha256", "fsroot_sha256"}}
        fixture.update(oid=1, checkpoint_xid=2)
        bounds = {"block_bytes": 4096, "block_count": 32768, "prefix_bytes": 40, "trailing_bytes": 1024}
        versions = {"rustc": "1.99.1"}
        padded = "APFS native extent probe 134218752 134217728 0 40 0 4096\n"
        transcript = f"""rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS native extent ledger {fixture['ledger_sha256']}
APFS native extent fixture {fixture['bootstrap_sha256']} {fixture['raw_sha256']}
APFS native extent oracle 14.7.2 23H311 arm64 2236.141.1 0 2
APFS native extent geometry 4096 32768 1 2 {fixture['wire_checksum']}
APFS native extent probe 134217728 134217728 0 40 0 4096
{padded}APFS native extent replay completed
"""
        verify_native_extent(transcript, fixture, bounds, versions)
        for old, replacement in ((padded, ""), ("0 40 0 4096", "0 40 4096 4096"),
                                 ("32768", "16384"), ("2236.141.1 0 2", "2236.141.1 1 2"),
                                 (fixture["bootstrap_sha256"], "f" * 64)):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, "probe facts"):
                verify_native_extent(transcript.replace(old, replacement), fixture, bounds, versions)

    def test_accepts_matching_candidate_and_transcript(self):
        self.assertEqual(self.check([self.record]), (1, "0.1.0", self.commit))

    def test_archive_digest_ignores_worktree_line_ending_configuration(self):
        (self.root / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")
        (self.root / "fixture.txt").write_bytes(b"first\nsecond\n")
        self.git("add", ".gitattributes", "fixture.txt")
        self.commit_policy()
        expected = self.digest
        self.git("config", "core.autocrlf", "true")
        self.git("config", "core.eol", "crlf")
        unpinned = subprocess.check_output(
            ["git", "-C", self.root, "-c", "tar.umask=0002", "archive", "--format=tar", self.commit]
        )
        self.assertNotEqual(hashlib.sha256(unpinned).hexdigest(), expected)
        self.assertEqual(archive_hash(self.root, self.commit), expected)

    def test_future_and_unscheduled_methods_do_not_activate_in_initial_release(self):
        for identifier, activation in (("A-V02", "0.8+"), ("A-V03", "later")):
            self.registry["obligations"].append({
                "id": identifier, "activation": activation, "mandatory_when_activated": True,
                "required_methods": ["native"],
            })
        self.commit_policy()
        self.record.update(commit=self.commit, source_hash=self.digest)
        self.assertEqual(self.check([self.record]), (1, "0.1.0", self.commit))

    def test_missing_duplicate_wrong_profile_and_incompatible_method(self):
        cases = [([], "missing evidence"), ([self.record, self.record], "duplicate evidence"),
                 ([self.record | {"profile": "other"}], "unexpected or duplicate evidence"),
                 ([self.record | {"method": "native"}], "does not match profile")]
        for records, expected in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(EvidenceError, expected):
                self.check(records)

    def test_release_mode_does_not_conflate_a_profile_pass_with_the_complete_matrix(self):
        self.registry["obligations"][0]["required_methods"].append("native")
        self.commit_policy()
        self.record.update(commit=self.commit, source_hash=self.digest)
        with self.assertRaisesRegex(EvidenceError, "release policy omits A-V01/native"):
            self.check([self.record])
        self.assertEqual(self.check([self.record], PROFILE), (1, "0.1.0", self.commit))

    def test_stale_commit_archive_or_dirty_candidate(self):
        for changes in ({"commit": "0" * 40}, {"source_hash": "0" * 64}):
            with self.subTest(changes=changes), self.assertRaisesRegex(EvidenceError, "stale evidence"):
                self.check([self.record | changes])
        for path in (self.root / "untracked", self.root / POLICY_PATH):
            with self.subTest(path=path):
                path.write_text("changed", encoding="utf-8")
                with self.assertRaisesRegex(EvidenceError, "checkout has tracked or untracked changes"):
                    self.check([self.record])
                if path == self.root / POLICY_PATH:
                    self.git("checkout", "--", POLICY_PATH)
                else:
                    path.unlink()

    def test_invocation_status_bounds_features_and_tools(self):
        cases = [({"status": "timeout"}, "clean successful"), ({"status": "unsupported"}, "clean successful"),
                 ({"dirty": True}, "clean successful"), ({"exit_code": False}, "clean successful"),
                 ({"bounds": {"scalar_bits": 32}}, "bounds"), ({"features": ["std"]}, "features"),
                 ({"command": ["bash", "other.sh"]}, "does not match profile"),
                 ({"tool_versions": {"kani": "0.68.0", "cbmc": "6.10.0"}}, "tool versions")]
        for changes, expected in cases:
            with self.subTest(changes=changes), self.assertRaisesRegex(EvidenceError, expected):
                self.check([self.record | changes])

    def test_transcript_digest_and_path_are_checked(self):
        self.log.write_text(TRANSCRIPT + "edited\n", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "artifact SHA-256 mismatch"):
            self.check([self.record])
        original = deepcopy(self.record)
        for uri in ("../kani.log", "/tmp/kani.log"):
            with self.subTest(uri=uri), self.assertRaisesRegex(EvidenceError, "artifact path"):
                self.record["artifacts"][0]["uri"] = uri
                self.check([self.record])
        self.record = original
        self.bundle = self.root.with_name("reports") / "bundle.json"
        self.bundle.parent.mkdir()
        (self.bundle.parent / self.log.name).symlink_to(self.log)
        with self.assertRaisesRegex(EvidenceError, "artifact escapes"):
            self.check([self.record])

    def test_vacuous_incomplete_or_off_scope_transcripts_are_rejected(self):
        cases = [("0 of 5 failed (1 unreachable)", "0 of 0 failed", "vacuous"),
                 ("1 unreachable", "5 unreachable", "vacuous"),
                 ("2 of 2 cover properties satisfied", "1 of 2 cover properties satisfied", "unreached"),
                 ("2 of 2 cover properties satisfied", "", "missing"),
                 ("CBMC 6.11.0", "CBMC 6.10.0", "wrong CBMC version"),
                 (f"Checking harness {HARNESS}", "Checking harness other", "unexpected Kani harness"),
                 ("0 failures, 1 total.", "1 failures, 1 total.", "incomplete Kani summary")]
        for old, replacement, expected in cases:
            self.set_transcript(TRANSCRIPT.replace(old, replacement))
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                self.check([self.record])

    def test_tlc_accepts_the_bounded_graph_and_requires_proof_counts_and_seed(self):
        self.set_tlc_profile()
        self.assertEqual(self.check([self.record], TLC_PROFILE), (1, "0.1.0", self.commit))
        with self.assertRaisesRegex(EvidenceError, "missing evidence for format-kani"):
            self.check([self.record])
        for changes, expected in (({"seed": "1"}, "TLC seed"), ({"proof": {"theorem": TLC_PROFILE}}, "metadata")):
            with self.subTest(changes=changes), self.assertRaisesRegex(EvidenceError, expected):
                self.check([self.record | changes], TLC_PROFILE)

    def test_tlc_rejects_incomplete_or_inconsistent_baseline_and_counterexample(self):
        self.set_tlc_profile()
        cases = [("13196 distinct states found", "1 distinct states found", "bounded state graph"),
                 ("0 states left on queue", "1 states left on queue", "bounded state graph"),
                 ("Finished checking temporal properties", "Skipped temporal properties", "temporal property check"),
                 ("with fp 0 and seed 0", "with fp 3 and seed 0", "TLC schedule"),
                 ("TLC2 Version 2.19", "TLC2 Version 2.20", "wrong TLC version"),
                 ("APFS TLC negative witness", "", "negative witness is missing"),
                 ("Invariant SelectionMatchesEvidence", "Invariant TypeOK", "expected counterexample"),
                 ("APFS TLC witness exit code: 12", "APFS TLC witness exit code: 0", "expected counterexample")]
        for old, replacement, expected in cases:
            self.set_transcript(TLC_TRANSCRIPT.replace(old, replacement))
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                self.check([self.record], TLC_PROFILE)

    def test_checksum_scenarios_pass_as_partial_evidence(self):
        self.set_checksum_profile()
        self.assertEqual(self.check([self.record], CHECKSUM_PROFILE), (1, "0.1.0", self.commit))
        with self.assertRaisesRegex(EvidenceError, "release policy omits A-V01/differential"):
            self.check([self.record])

    def test_checksum_requires_the_named_objects_matrix_and_completion(self):
        self.set_checksum_profile()
        pattern = "APFS checksum uniform 4096 0"
        cases = [("native-block-0.bin", "native-block-1.bin", "checksum scenarios"),
                 ("46653a58ffa467b1", "0000000000000001", "checksum scenarios"),
                 ("4096 0 2048", "4096 0 2044", "checksum scenarios"),
                 (pattern, "", "checksum scenarios"),
                 (pattern, f"{pattern}\n{pattern}", "checksum scenarios"),
                 ("differential completed", "differential interrupted", "did not complete"),
                 ("rustc 1.99.1", "rustc 1.100.0", "wrong Rust version")]
        for old, replacement, expected in cases:
            self.set_transcript(CHECKSUM_TRANSCRIPT.replace(old, replacement))
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                self.check([self.record], CHECKSUM_PROFILE)

    def test_bootstrap_properties_pass_as_partial_evidence(self):
        self.set_bootstrap_profile()
        self.assertEqual(self.check([self.record], BOOTSTRAP_PROFILE), (1, "0.1.0", self.commit))
        with self.assertRaisesRegex(EvidenceError, "release policy omits A-V01/property"):
            self.check([self.record])

    def test_container_property_method_requires_all_scoped_profiles(self):
        repository = Path(__file__).resolve().parents[1]
        policy = json.loads((repository / POLICY_PATH).read_text())
        registry = json.loads((repository / REGISTRY_PATH).read_text())
        method = "A-V01/property"
        profiles = required_matrix(policy, registry, None, method)
        self.assertEqual(set(profiles), {
            "bootstrap-properties", "locator-properties", "geometry-span-properties",
            "native-checksum-window-properties", "native-size-matrix-window-properties",
            "complete-object-properties",
        })
        with self.assertRaises(EvidenceError) as full_release:
            required_matrix(policy, registry, None)
        self.assertNotIn(method, str(full_release.exception))
        self.assertIn("A-V02/property", str(full_release.exception))

        omitted = deepcopy(policy)
        del omitted["profiles"]["geometry-span-properties"]
        renamed_command = deepcopy(policy)
        renamed_command["profiles"]["locator-properties"]["command"][-1] = "unrelated.sh"
        shortened = deepcopy(policy)
        shortened["profiles"]["geometry-span-properties"]["bounds"]["cases_per_shape"] = 1
        cutoff = deepcopy(policy)
        cutoff["profiles"]["bootstrap-properties"]["property_cases"]["candidate-feature-cutoff"] = [[8, 1, 11]]
        for incomplete in (omitted, renamed_command, shortened, cutoff):
            with self.subTest(incomplete=incomplete), self.assertRaisesRegex(EvidenceError, "no complete configured"):
                required_matrix(incomplete, registry, None, method)

    def test_container_differential_method_requires_all_scoped_profiles(self):
        repository = Path(__file__).resolve().parents[1]
        policy = json.loads((repository / POLICY_PATH).read_text())
        registry = json.loads((repository / REGISTRY_PATH).read_text())
        method = "A-V01/differential"
        profiles = required_matrix(policy, registry, None, method)
        self.assertEqual(set(profiles), {
            "bootstrap-admission-differential", "format-checksum-differential",
            "format-native-geometry-differential", "format-native-size-matrix-differential",
        })
        with self.assertRaises(EvidenceError) as full_release:
            required_matrix(policy, registry, None)
        self.assertNotIn(method, str(full_release.exception))
        self.assertIn("A-V02/differential", str(full_release.exception))

        omitted = deepcopy(policy)
        del omitted["profiles"]["bootstrap-admission-differential"]
        reduced = deepcopy(policy)
        reduced["profiles"]["format-checksum-differential"]["checksum_cases"]["fixtures"].popitem()
        for incomplete in (omitted, reduced):
            with self.subTest(incomplete=incomplete), self.assertRaisesRegex(EvidenceError, "no complete configured"):
                required_matrix(incomplete, registry, None, method)

    def test_bootstrap_properties_require_the_boundary_matrix(self):
        self.set_bootstrap_profile()
        line = "APFS bootstrap property required-feature 63"
        cases = [("4096 7 3 24", "4096 7 1 8", "bootstrap property scenarios"),
                 ("checksum-window 65 9", "checksum-window 65 8", "bootstrap property scenarios"),
                 ("typed-required-feature 4034 16136", "typed-required-feature 4033 16132", "bootstrap property scenarios"),
                 ("mixed-feature-cutoff 4096 32", "mixed-feature-cutoff 4096 31", "bootstrap property scenarios"),
                 ("geometry-cutoff 4096 4 12", "geometry-cutoff 4096 4 11", "bootstrap property scenarios"),
                 ("candidate-feature-cutoff 8 2 11", "", "bootstrap property scenarios"),
                 (line, "", "bootstrap property scenarios"),
                 (line, f"{line}\n{line}", "bootstrap property scenarios"),
                 ("properties completed", "properties interrupted", "did not complete"),
                 ("rustc 1.99.1", "rustc 1.100.0", "wrong Rust version")]
        for old, replacement, expected in cases:
            self.set_transcript(BOOTSTRAP_TRANSCRIPT.replace(old, replacement))
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                self.check([self.record], BOOTSTRAP_PROFILE)

    def test_locator_transcripts_require_seed_tool_and_each_case(self):
        transcript = """rustc 1.99.1 (58cf8f9c3 2026-10-13)
proptest v1.12.0
   Compiling proptest v1.12.0
APFS locator seed 7
APFS locator property descriptor 4096 fragment-locator 64
APFS locator properties completed
"""
        cases = {"layouts": ["descriptor"], "block_sizes": [4096], "scenarios": ["fragment-locator"]}
        bounds = {"seed": 7, "cases_per_scenario": 64}
        versions = {"rustc": "1.99.1", "proptest": "1.12.0"}
        verify_locator_properties(transcript, cases, bounds, versions)
        for old, replacement, expected in [
            ("seed 7", "seed 8", "seed"), ("v1.12.0", "v1.11.0", "tool versions"),
            ("fragment-locator 64", "fragment-locator 63", "property scenarios"),
            ("descriptor 4096", "data 4096", "property scenarios"),
            ("properties completed", "properties interrupted", "did not complete"),
        ]:
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                verify_locator_properties(transcript.replace(old, replacement), cases, bounds, versions)

    def test_span_transcript_requires_zero_entries_and_each_bound_query(self):
        transcript = """rustc 1.99.1 (test)
proptest v1.12.0
APFS span seed 7
APFS span property native 4096 0 64 192
APFS span property native 4096 1 64 256
APFS span properties completed
"""
        cases = {"native": [4096]}
        bounds = {"seed": 7, "cases_per_shape": 64, "max_entries": 1, "boundary_ranges": 3}
        versions = {"rustc": "1.99.1", "proptest": "1.12.0"}
        verify_span_properties(transcript, cases, bounds, versions)
        for old, replacement, expected in (
            ("APFS span seed 7", "APFS span seed 8", "seed"),
            ("native 4096 0 64 192", "native 4096 1 64 256", "span property scenarios"),
            ("64 256", "64 255", "span property scenarios"),
            ("span properties completed", "span properties interrupted", "did not complete"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                verify_span_properties(transcript.replace(old, replacement), cases, bounds, versions)

    def test_native_windows_require_the_complete_count_for_each_fixture(self):
        row = "APFS native window native-block-0.bin 4096 1017 46653a58ffa467b1"
        transcript = "\n".join(["rustc 1.99.1 (test)", row, "APFS native windows completed"])
        fixtures = {"native-block-0.bin": "46653a58ffa467b1"}
        bounds = {"object_bytes": 4096, "minimum_prefix_bytes": 32, "word_bytes": 4}
        versions = {"rustc": "1.99.1"}
        verify_native_windows(transcript, fixtures, bounds, versions)
        for old, replacement, error in (
            ("1017", "1016", "window scenarios"),
            (row, row + "\n" + row, "window scenarios"),
            ("native-block-0.bin", "native-block-1.bin", "window scenarios"),
            ("46653a58ffa467b1", "0000000000000001", "window scenarios"),
            ("windows completed", "windows interrupted", "did not complete"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, error):
                verify_native_windows(transcript.replace(old, replacement), fixtures, bounds, versions)

    def test_native_window_matrix_requires_the_ledger_and_all_per_size_counts(self):
        name = "native-size-matrix-window-properties"
        root = Path(__file__).resolve().parents[1]
        profile = json.loads((root / POLICY_PATH).read_text(encoding="utf-8"))["profiles"][name]
        fixtures = profile["window_cases"]
        bounds = profile["bounds"]
        verify_native_window_policy(name, profile)
        with self.assertRaisesRegex(EvidenceError, "matrix bounds"):
            verify_native_window_policy(name, profile | {"bounds": bounds | {"block_sizes": [4096]}})
        with self.assertRaisesRegex(EvidenceError, "matrix sizes"):
            cases = fixtures | {"checksums": {"4096": fixtures["checksums"]["4096"]}}
            verify_native_window_policy(name, profile | {"window_cases": cases})

        row = "APFS native window matrix 65536 16377 49160 4bcc7609f30e3ca2"
        transcript = "\n".join([
            "rustc 1.99.1 (test)",
            f"APFS native window matrix ledger {fixtures['ledger_sha256']}",
            "APFS native window matrix 4096 1017 3080 ff6b7d4b7fef6594",
            "APFS native window matrix 8192 2041 6152 93dfe781b706a414",
            "APFS native window matrix 16384 4089 12296 5f28f8fa40ab799f",
            "APFS native window matrix 32768 8185 24584 0f77b0d4dc4116d7",
            row,
            "APFS native windows completed",
        ])
        versions = profile["tool_versions"]
        verify_native_windows(transcript, fixtures, bounds, versions)
        for old, replacement in (
            (row, ""),
            (row, row + "\n" + row),
            ("16377 49160", "16376 49161"),
            (fixtures["ledger_sha256"], "a" * 64),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, "window scenarios"):
                verify_native_windows(transcript.replace(old, replacement), fixtures, bounds, versions)

    def test_complete_objects_require_each_size_and_its_compared_windows_ranges_and_profiles(self):
        transcript = "\n".join([
            "rustc 1.99.1 (test)", "proptest v1.12.0", "APFS complete object seed 7",
            "APFS complete object property 4096 64 320 192 512",
            "APFS complete object property 65536 64 320 192 512",
            "APFS complete object properties completed",
        ])
        sizes = [4096, 65536]
        bounds = {"seed": 7, "cases_per_block_size": 64, "checksum_windows_per_object": 5,
                  "byte_ranges_per_object": 3, "compatible_profiles_per_object": 8}
        versions = {"rustc": "1.99.1", "proptest": "1.12.0"}
        verify_complete_objects(transcript, sizes, bounds, versions)
        for old, replacement, error in (
            ("seed 7", "seed 8", "seed"),
            ("65536 64", "4096 64", "property scenarios"),
            ("320 192", "319 192", "property scenarios"),
            ("320 192", "320 191", "property scenarios"),
            ("192 512", "192 511", "property scenarios"),
            ("properties completed", "properties interrupted", "did not complete"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, error):
                verify_complete_objects(transcript.replace(old, replacement), sizes, bounds, versions)

    def test_checkpoint_model_transcript_requires_each_state_and_request_pair(self):
        cases = {"states": ["Complete", "TornDescriptor"], "requests": ["automatic", "1", "2"]}
        versions = {"rustc": "1.99.1"}
        lines = ["rustc 1.99.1 (58cf8f9c3 2026-10-13)"]
        lines.extend(f"APFS checkpoint model {early} {latest} {request}"
                     for early in cases["states"] for latest in cases["states"] for request in cases["requests"])
        lines.append("APFS checkpoint model completed")
        transcript = "\n".join(lines) + "\n"
        verify_checkpoint_model(transcript, cases, versions)
        row = "APFS checkpoint model Complete TornDescriptor 1"
        for old, replacement, expected in (
            (row, "", "checkpoint model scenarios"),
            (row, row + "\n" + row, "checkpoint model scenarios"),
            (row, row.replace(" 1", " 3"), "checkpoint model scenarios"),
            ("model completed", "model interrupted", "did not complete"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                verify_checkpoint_model(transcript.replace(old, replacement), cases, versions)

    def test_checkpoint_layout_transcript_checks_exact_ring_and_request(self):
        transcript = """rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS checkpoint layout 8 1 Wrap Ascending automatic
APFS checkpoint layout 8 1 Wrap Ascending 16
APFS checkpoint layouts completed
"""
        matrix = {"ring_slots": [8], "candidate_counts": [1], "placements": ["Wrap"], "orders": ["Ascending"]}
        bounds = {"first_xid": 16, "cases": 2}
        versions = {"rustc": "1.99.1"}
        verify_checkpoint_layouts(transcript, matrix, bounds, versions)
        row = "APFS checkpoint layout 8 1 Wrap Ascending 16"
        for old, replacement, expected in (
            (row, "", "checkpoint layout cases"),
            (row, f"{row}\n{row}", "checkpoint layout cases"),
            (" 16", " 17", "checkpoint layout cases"),
            (" 8 1 Wrap", " 16 1 Wrap", "checkpoint layout cases"),
            ("layouts completed", "layouts interrupted", "did not complete"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                verify_checkpoint_layouts(transcript.replace(old, replacement), matrix, bounds, versions)

    def test_native_checkpoint_transcript_requires_provenance_and_replayed_slots(self):
        fixtures = {
            "ledger_set_sha256": "a" * 64, "os_version": "14.7.2", "os_build": "23H311",
            "architecture": "arm64", "oracle_version": "2236.141.1", "snapshots": {
                "sample": {"ledger_sha256": "b" * 64, "packed_sha256": "c" * 64, "raw_sha256": "d" * 64,
                           "xid": 4, "descriptor": 8, "next_slot": 0,
                           "live_slots": [6, 7], "descriptor_xids": [1, 2, 3, 4], "payload_blocks": [19, 20, 21, 22]},
            },
        }
        bounds = {"descriptor_ring_slots": 8}
        versions = {"rustc": "1.99.1"}
        transcript = f"""rustc 1.99.1 (58cf8f9c3 2026-10-13)
APFS native checkpoints ledgers {'a' * 64}
APFS native checkpoints fixture sample {'b' * 64} {'c' * 64} {'d' * 64}
APFS native checkpoints oracle sample 14.7.2 23H311 arm64 2236.141.1 0 4
APFS native checkpoints replay sample 4 8 8 0 [6, 7] [1, 2, 3, 4] [19, 20, 21, 22]
APFS native checkpoints replay completed
"""
        verify_native_checkpoints(transcript, fixtures, bounds, versions)
        independent = "APFS checkpoint differential matched sample 4 8 8 0 [6, 7] [1, 2, 3, 4] [19, 20, 21, 22]\n"
        complete = "APFS checkpoint differential completed\n"
        verify_checkpoint_differential(transcript + independent + complete, fixtures, bounds, versions)
        with self.assertRaisesRegex(EvidenceError, "inconsistent independent checkpoint comparisons"):
            verify_checkpoint_differential(transcript + independent.replace(" 4 8 8", " 6 8 8") + complete,
                                           fixtures, bounds, versions)
        for old, replacement, expected in (
            ("a" * 64, "f" * 64, "disagree"),
            ("c" * 64, "f" * 64, "disagree"),
            ("2236.141.1 0 4", "2236.141.1 1 4", "disagree"),
            ("[6, 7]", "[7, 0]", "disagree"),
            ("[19, 20, 21, 22]", "[19, 20, 21, 23]", "disagree"),
            ("replay completed", "replay interrupted", "did not complete"),
        ):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, expected):
                verify_native_checkpoints(transcript.replace(old, replacement), fixtures, bounds, versions)


    def test_native_replay_passes_as_partial_evidence(self):
        self.set_native_profile()
        self.assertEqual(self.check([self.record], NATIVE_PROFILE), (1, "0.1.0", self.commit))
        with self.assertRaisesRegex(EvidenceError, "release policy omits A-V01/native"):
            self.check([self.record])

    def test_native_replay_requires_fixture_identity_and_all_scenarios(self):
        self.set_native_profile()
        for value in (None, "f" * 64):
            record = dict(self.record, fixture_hash=value)
            with self.subTest(value=value), self.assertRaisesRegex(EvidenceError, "native fixture hash"):
                self.check([record], NATIVE_PROFILE)

        refusal = "APFS native bootstrap refused count 2"
        for old, new, error in (
            ("2236.141.1 0 4", "2236.141.1 0 3", "replay facts"),
            ("c" * 64, "f" * 64, "replay facts"),
            ("16384 4 dd9368444871caee", "16384 5 dd9368444871caee", "replay facts"),
            (refusal, "", "replay facts"),
            (refusal, f"{refusal}\n{refusal}", "replay facts"),
            ("refused size 1", "refused size 2", "replay facts"),
            ("replay completed", "replay interrupted", "did not complete"),
        ):
            with self.subTest(change=new), self.assertRaisesRegex(EvidenceError, error):
                self.set_transcript(NATIVE_TRANSCRIPT.replace(old, new))
                self.check([self.record], NATIVE_PROFILE)


class FormatFuzzTranscriptTests(unittest.TestCase):
    def test_requires_pinned_address_sanitizer_corpus_and_run_count(self):
        transcript = "\n".join([
            "rustc 1.101.0-nightly (test)", "cargo-fuzz 0.13.2", "libfuzzer-sys v0.4.13",
            "APFS format fuzz AddressSanitizer nightly-2026-11-04 seed 7 runs 20000 max-request-bytes 17",
            "INFO: Seed: 7", "INFO: seed corpus: files: 58 min: 17b max: 17b total: 986b rss: 50Mb",
            "#20000\tDONE   cov: 173 ft: 218", "Done 20000 runs in 0 second(s)",
            "APFS format requests fuzz completed",
        ])
        bounds = {"seed": 7, "runs": 20000, "max_request_bytes": 17, "seed_requests": 58}
        versions = {"rustc": "1.101.0-nightly", "toolchain": "nightly-2026-11-04",
                    "cargo-fuzz": "0.13.2", "libfuzzer-sys": "0.4.13"}
        verify_format_fuzz(transcript, bounds, versions)
        for original, replacement, reason in [
            ("libfuzzer-sys v0.4.13", "libfuzzer-sys v0.4.12", "tool versions"),
            ("AddressSanitizer nightly", "MemorySanitizer nightly", "sanitizer or seed"),
            ("Seed: 7", "Seed: 8", "sanitizer or seed"),
            ("files: 58", "files: 57", "seed corpus"),
            ("#20000", "#19999", "complete the required observations"),
            ("cov: 173", "cov: 0", "complete the required observations"),
            ("Done 20000", "Done 19999", "complete the required observations"),
            ("Done 20000", "ERROR: AddressSanitizer\nDone 20000", "runtime error"),
        ]:
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, reason):
                verify_format_fuzz(transcript.replace(original, replacement), bounds, versions)


class NativeGeometryTranscriptTests(unittest.TestCase):
    def test_requires_all_five_native_matrix_sizes_and_exact_row_groups(self):
        name = "format-native-size-matrix-differential"
        root = Path(__file__).resolve().parents[1]
        profile = json.loads((root / POLICY_PATH).read_text(encoding="utf-8"))["profiles"][name]
        verify_native_geometry_policy(name, profile)
        for field, value in (("block_sizes", [4096, 8192]), ("source_bytes", 64 << 20)):
            changed = profile | {"bounds": profile["bounds"] | {field: value}}
            with self.subTest(field=field), self.assertRaisesRegex(EvidenceError, "matrix bounds"):
                verify_native_geometry_policy(name, changed)
        for field, count in (("nxsb", 4), ("area", 9), ("map", 1), ("profile", True)):
            cases = profile["geometry_cases"]
            changed = profile | {"geometry_cases": cases | {"rows": cases["rows"] | {field: count}}}
            with self.subTest(field=field), self.assertRaisesRegex(EvidenceError, "geometry.*rows"):
                verify_native_geometry_policy(name, changed)

    def test_requires_actual_geometry_rows_matching_the_comparison_digest(self):
        rows = [
            "APFS native geometry nxsb 0 2 4096 16384 67108864 199 2",
            "APFS native geometry area 0 data 9 160 2 4 6 36864 692224",
            "APFS native geometry map 3 2 1 1",
            "APFS native geometry mapping 3 0 2147483653 0 4096 0 1024 11 45056 49152",
            "APFS native geometry header 0 46653a58ffa467b1 1 2 2147483649 0",
            "APFS native geometry profile 0 0 0 2 0 0",
        ]
        digest = hashlib.sha256("\n".join(sorted(rows)).encode("ascii")).hexdigest()
        ledger = "a" * 64
        transcript = "\n".join([
            "rustc 1.99.1 (test)", *rows,
            f"APFS native geometry ledger {ledger}",
            f"APFS native geometry comparison 1 1 1 1 1 1 {digest}",
            "APFS native geometry differential completed",
        ])
        cases = {"ledger_sha256": ledger, "rows_sha256": digest,
                 "rows": {"nxsb": 1, "area": 1, "map": 1, "mapping": 1, "header": 1, "profile": 1}}
        versions = {"rustc": "1.99.1"}
        verify_native_geometry(transcript, cases, versions)
        for old, replacement, message in [
            (rows[0], "", "row counts"),
            (rows[1], rows[1] + "\n" + rows[1], "row counts"),
            ("45056 49152", "45056 49151", "independent comparison"),
            (rows[4], rows[4].replace("2147483649", "2147483650"), "independent comparison"),
            (rows[5], rows[5].replace("0 2 0 0", "0 2 1 0"), "independent comparison"),
            (ledger, "b" * 64, "ledger or comparison"),
            ("differential completed", "differential interrupted", "did not complete"),
        ]:
            with self.subTest(replacement=replacement), self.assertRaisesRegex(EvidenceError, message):
                verify_native_geometry(transcript.replace(old, replacement), cases, versions)


if __name__ == "__main__":
    unittest.main()
