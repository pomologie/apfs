"""Exercise APFS profile and release evidence checks in disposable repositories."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from check_release_evidence import EvidenceError, POLICY_PATH, REGISTRY_PATH, archive_hash, validate


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


if __name__ == "__main__":
    unittest.main()
