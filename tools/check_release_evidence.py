#!/usr/bin/env python3
"""Validate an APFS evidence bundle against an exact clean Git candidate."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from apfs_evidence_transcript import (
    EvidenceError, require, verify_bootstrap_properties, verify_checkpoint_layouts, verify_checkpoint_model,
    NATIVE_GEOMETRY_GROUPS, verify_checksum_differential, verify_native_geometry,
    verify_kani, verify_locator_properties, verify_native_bootstrap, verify_native_checkpoints, verify_span_properties,
    verify_tlc,
)


POLICY_PATH = "verification/release-profile.json"
REGISTRY_PATH = "verification/obligations.json"
SCHEMA_VERSION = 1
UNSCHEDULED = {"later", "stretch"}
SHA256 = re.compile(r"[0-9a-f]{64}")
RECORD_FIELDS = {
    "schema_version", "obligation_id", "method", "status", "commit", "dirty",
    "source_hash", "profile", "features", "tool_versions", "command", "assumptions",
    "bounds", "artifacts", "runner", "duration_ms", "exit_code",
}
OPTIONAL_RECORD_FIELDS = {"seed", "trace_hash", "fixture_hash", "proof"}
PROFILE_FIELDS = {"obligation", "method", "features", "command", "tool_versions", "bounds"}
TLC_MODEL_FIELDS = {"name", "initial_states", "states", "distinct_states", "depth", "violated_invariant"}
TLC_BOUND_FIELDS = {"candidate_xids", "ring_slots", "workers", "seed", "fingerprint_index"}
CHECKSUM_BOUND_FIELDS = {"fixture_bytes", "max_block_bytes", "distinct_word"}
CHECKSUM_CASE_FIELDS = {"fixtures", "block_sizes", "uniform_words"}
UINT32_MAX = 2**32 - 1
BOOTSTRAP_PROPERTY_COLUMNS = {"size-prefix": 2, "geometry": 4, "checksum-window": 2, "required-feature": 1}
NATIVE_BOOTSTRAP_HASH_FIELDS = {"ledger_sha256", "raw_sha256", "metadata_sha256", "bootstrap_sha256", "fsroot_sha256"}
NATIVE_BOOTSTRAP_ID_FIELDS = {"os_version", "os_build", "architecture", "oracle_version"}
NATIVE_BOOTSTRAP_REFUSALS = {"size", "count", "type", "checksum", "required-feature"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key}")
        result[key] = value
    return result


def invalid_json_constant(value):
    raise EvidenceError(f"invalid JSON constant {value}")


def parse_json(data):
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_json_constant)


def git_output(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    require(result.returncode == 0, f"Git {args[0]} failed")
    return result.stdout


def archive_hash(root, commit):
    args = ["git", "-C", str(root), "-c", "tar.umask=0002", "-c", "core.autocrlf=false",
            "-c", "core.eol=lf", "archive", "--format=tar", commit]
    with subprocess.Popen(args, stdout=subprocess.PIPE) as process:
        digest = hashlib.file_digest(process.stdout, "sha256").hexdigest()
        require(process.wait() == 0, "could not archive the candidate")
    return digest


def version(value):
    require(isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value),
            "invalid milestone version")
    return tuple(map(int, value.split(".")))


def activation_version(value):
    if isinstance(value, str) and re.fullmatch(r"\d+\.\d+\+", value):
        return version(value[:-1] + ".0")
    return version(value)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def text_list(values):
    return isinstance(values, list) and all(text(value) for value in values)


def text_mapping(values):
    return isinstance(values, dict) and all(text(key) and text(value) for key, value in values.items())


def positive_integer(value):
    return type(value) is int and value > 0


def verify_method_policy(name, profile):
    method = profile["method"]
    bounds = profile["bounds"]
    versions = profile["tool_versions"]
    require(text_mapping(versions), f"invalid tool versions for {name}")
    require(isinstance(bounds, dict) and bounds, f"missing bounds for {name}")
    if method == "kani":
        require(set(profile) == PROFILE_FIELDS | {"harnesses"} and {"kani", "cbmc"} <= versions.keys(),
                f"invalid Kani policy for {name}")
        harnesses = profile["harnesses"]
        require(isinstance(harnesses, dict) and harnesses and all(
            text(harness) and positive_integer(count) for harness, count in harnesses.items()
        ), f"no non-vacuous harnesses for {name}")
    elif method == "tlc":
        require(set(profile) == PROFILE_FIELDS | {"model"} and {"tlc", "java"} <= versions.keys(),
                f"invalid TLC policy for {name}")
        require(set(bounds) == TLC_BOUND_FIELDS and all(positive_integer(bounds[key])
                for key in ("candidate_xids", "ring_slots", "workers"))
                and all(type(bounds[key]) is int and bounds[key] >= 0 for key in ("seed", "fingerprint_index")),
                f"invalid TLC bounds for {name}")
        model = profile["model"]
        require(isinstance(model, dict) and set(model) == TLC_MODEL_FIELDS and text(model["name"])
                and text(model["violated_invariant"]) and all(positive_integer(model[key])
                for key in ("initial_states", "distinct_states", "states", "depth"))
                and model["initial_states"] < model["distinct_states"] <= model["states"],
                f"no non-vacuous TLC model for {name}")
    elif method == "differential":
        if "geometry_cases" in profile:
            verify_native_geometry_policy(name, profile)
            return
        require(set(profile) == PROFILE_FIELDS | {"checksum_cases", "partial"} and profile["partial"] is True
                and "rustc" in versions, f"invalid checksum differential policy for {name}")
        verify_checksum_policy(name, profile["checksum_cases"], bounds)
    elif method == "property":
        if "checkpoint_layouts" in profile:
            verify_checkpoint_layout_policy(name, profile)
            return
        if "checkpoint_cases" in profile:
            verify_checkpoint_model_policy(name, profile)
            return
        if "locator_cases" in profile:
            verify_locator_policy(name, profile)
            return
        if "span_cases" in profile:
            verify_span_policy(name, profile)
            return
        require(set(profile) == PROFILE_FIELDS | {"property_cases", "partial"} and profile["partial"] is True
                and "rustc" in versions, f"invalid bootstrap property policy for {name}")
        cases = profile["property_cases"]
        require(isinstance(cases, dict) and set(cases) == BOOTSTRAP_PROPERTY_COLUMNS.keys(),
                f"incomplete bootstrap property coverage for {name}")
        for case, columns in BOOTSTRAP_PROPERTY_COLUMNS.items():
            rows = cases[case]
            require(isinstance(rows, list) and rows and all(isinstance(row, list) and len(row) == columns
                    and all(positive_integer(value) for value in row) for row in rows)
                    and len({tuple(row) for row in rows}) == len(rows), f"invalid {case} rows for {name}")
    elif method == "native":
        if "native_checkpoints" in profile:
            verify_native_checkpoint_policy(name, profile)
        else:
            verify_native_bootstrap_policy(name, profile)
    else:
        raise EvidenceError(f"no transcript verifier for {name}")


def verify_native_geometry_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"geometry_cases", "partial"} and profile["partial"] is True
            and "rustc" in profile["tool_versions"], f"invalid native geometry policy for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"block_bytes", "source_bytes"} and all(positive_integer(value) for value in bounds.values())
            and bounds["source_bytes"] % bounds["block_bytes"] == 0, f"invalid native geometry bounds for {name}")
    cases = profile["geometry_cases"]
    require(isinstance(cases, dict) and set(cases) == {"ledger_sha256", "rows_sha256", "rows"},
            f"invalid native geometry case matrix for {name}")
    require(all(isinstance(cases[key], str) and SHA256.fullmatch(cases[key])
                for key in ("ledger_sha256", "rows_sha256")), f"invalid native geometry digests for {name}")
    rows = cases["rows"]
    require(isinstance(rows, dict) and set(rows) == set(NATIVE_GEOMETRY_GROUPS)
            and all(positive_integer(count) for count in rows.values()), f"incomplete native geometry rows for {name}")


def verify_checksum_policy(name, cases, bounds):
    require(set(bounds) == CHECKSUM_BOUND_FIELDS and all(positive_integer(value) for value in bounds.values())
            and bounds["distinct_word"] <= UINT32_MAX, f"invalid checksum bounds for {name}")
    require(isinstance(cases, dict) and set(cases) == CHECKSUM_CASE_FIELDS, f"invalid checksum cases for {name}")
    fixtures = cases["fixtures"]
    require(text_mapping(fixtures) and fixtures and all(re.fullmatch(r"[0-9a-f]{16}", checksum)
            for checksum in fixtures.values()), f"invalid fixture checksums for {name}")
    sizes, words = cases["block_sizes"], cases["uniform_words"]
    require(isinstance(sizes, list) and sizes and all(positive_integer(size) and size >= 32 and size % 4 == 0
            for size in sizes) and len(set(sizes)) == len(sizes) and max(sizes) == bounds["max_block_bytes"]
            and bounds["fixture_bytes"] in sizes, f"invalid checksum sizes for {name}")
    require(isinstance(words, list) and words and all(type(word) is int and 0 <= word <= UINT32_MAX for word in words)
            and len(set(words)) == len(words) and bounds["distinct_word"] not in words,
            f"invalid checksum word patterns for {name}")


def verify_locator_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"locator_cases", "partial"} and profile["partial"] is True
            and {"rustc", "proptest"} <= profile["tool_versions"].keys(), f"invalid locator policy for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"seed", "cases_per_scenario", "address_bits", "area_field_bits"}
            and all(positive_integer(value) for value in bounds.values()), f"invalid locator bounds for {name}")
    cases = profile["locator_cases"]
    require(isinstance(cases, dict) and set(cases) == {"layouts", "block_sizes", "scenarios"},
            f"invalid locator matrix for {name}")
    require(cases["layouts"] == ["descriptor", "data"] and cases["block_sizes"] == [4096, 8192, 16384, 32768, 65536],
            f"incomplete locator layouts or block sizes for {name}")
    scenarios = cases["scenarios"]
    require(text_list(scenarios) and scenarios and len(set(scenarios)) == len(scenarios),
            f"incomplete locator scenarios for {name}")


def verify_span_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"span_cases", "partial"} and profile["partial"] is True
            and {"rustc", "proptest"} <= profile["tool_versions"].keys(), f"invalid span policy for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"seed", "cases_per_shape", "max_entries", "boundary_ranges", "scalar_bits"}
            and all(positive_integer(value) for value in bounds.values())
            and (bounds["max_entries"], bounds["boundary_ranges"], bounds["scalar_bits"]) == (8, 3, 64),
            f"invalid geometry span bounds for {name}")
    require(profile["span_cases"] == {"native": [4096], "synthetic": [4096, 8192, 16384, 32768, 65536]},
            f"incomplete geometry span source profiles for {name}")


def verify_checkpoint_model_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"checkpoint_cases", "partial"} and profile["partial"] is True
            and "rustc" in profile["tool_versions"], f"invalid checkpoint model policy for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"candidate_xids", "descriptor_ring_slots", "cases"}
            and all(positive_integer(value) for value in bounds.values()), f"invalid checkpoint model bounds for {name}")
    cases = profile["checkpoint_cases"]
    require(isinstance(cases, dict) and set(cases) == {"states", "requests"}, f"invalid checkpoint model cases for {name}")
    states, requests = cases["states"], cases["requests"]
    require(text_list(states) and states and len(set(states)) == len(states)
            and text_list(requests) and len(set(requests)) == bounds["candidate_xids"] + 1
            and len(set(requests)) == len(requests) and "automatic" in requests
            and len(states) ** 2 * len(requests) == bounds["cases"], f"incomplete checkpoint scenario matrix for {name}")


def verify_checkpoint_layout_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"checkpoint_layouts", "partial"} and profile["partial"] is True
            and "rustc" in profile["tool_versions"], f"invalid checkpoint layout policy for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"first_xid", "cases"} and all(positive_integer(value) for value in bounds.values()),
            f"invalid checkpoint layout bounds for {name}")
    matrix = profile["checkpoint_layouts"]
    require(isinstance(matrix, dict) and set(matrix) == {"ring_slots", "candidate_counts", "placements", "orders"},
            f"invalid checkpoint layout matrix for {name}")
    for axis in ("ring_slots", "candidate_counts"):
        values = matrix[axis]
        require(isinstance(values, list) and values and all(positive_integer(value) for value in values)
                and len(set(values)) == len(values), f"invalid checkpoint layout axis {axis}")
    require(matrix["placements"] == ["Start", "Middle", "Wrap"] and matrix["orders"] == ["Ascending", "Descending"]
            and min(matrix["ring_slots"]) >= 2 * max(matrix["candidate_counts"]),
            f"incomplete checkpoint layout matrix for {name}")


def verify_native_bootstrap_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"native_fixture", "partial"} and profile["partial"] is True
            and "rustc" in profile["tool_versions"], f"invalid native bootstrap policy for {name}")
    fixture = profile["native_fixture"]
    require(isinstance(fixture, dict) and set(fixture) == NATIVE_BOOTSTRAP_HASH_FIELDS | NATIVE_BOOTSTRAP_ID_FIELDS
            | {"checkpoint_xid", "wire_checksum"}, f"incomplete native fixture for {name}")
    require(all(isinstance(fixture[key], str) and SHA256.fullmatch(fixture[key])
                for key in NATIVE_BOOTSTRAP_HASH_FIELDS), f"invalid native fixture hashes for {name}")
    require(all(text(fixture[key]) and len(fixture[key].split()) == 1 for key in NATIVE_BOOTSTRAP_ID_FIELDS)
            and positive_integer(fixture["checkpoint_xid"]) and isinstance(fixture["wire_checksum"], str)
            and re.fullmatch(r"[0-9a-f]{16}", fixture["wire_checksum"]), f"invalid native fixture identity for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"block_bytes", "block_count", "admitted_reads", "refused_reads"}
            and all(positive_integer(bounds[key]) for key in ("block_bytes", "block_count", "admitted_reads")),
            f"invalid native bootstrap bounds for {name}")
    refusals = bounds["refused_reads"]
    require(isinstance(refusals, dict) and set(refusals) == NATIVE_BOOTSTRAP_REFUSALS
            and all(positive_integer(reads) for reads in refusals.values()), f"incomplete native refusals for {name}")


def verify_native_checkpoint_policy(name, profile):
    require(set(profile) == PROFILE_FIELDS | {"native_checkpoints", "partial"} and profile["partial"] is True
            and "rustc" in profile["tool_versions"], f"invalid native checkpoint policy for {name}")
    bounds = profile["bounds"]
    require(set(bounds) == {"descriptor_ring_slots", "snapshots"}
            and all(positive_integer(value) for value in bounds.values()), f"invalid native checkpoint bounds for {name}")
    fixtures = profile["native_checkpoints"]
    require(isinstance(fixtures, dict) and set(fixtures) == NATIVE_BOOTSTRAP_ID_FIELDS
            | {"ledger_set_sha256", "snapshots"}, f"invalid native checkpoint fixture metadata for {name}")
    require(all(text(fixtures[key]) for key in NATIVE_BOOTSTRAP_ID_FIELDS)
            and text(fixtures["ledger_set_sha256"]) and SHA256.fullmatch(fixtures["ledger_set_sha256"]),
            f"invalid native checkpoint provenance for {name}")
    snapshots = fixtures["snapshots"]
    require(isinstance(snapshots, dict) and len(snapshots) == bounds["snapshots"], f"incomplete native checkpoints for {name}")
    hashes = {"ledger_sha256", "packed_sha256", "raw_sha256"}
    rows = {"live_slots", "descriptor_xids", "payload_blocks"}
    for label, snapshot in snapshots.items():
        require(text(label) and isinstance(snapshot, dict) and set(snapshot) == hashes | rows | {"xid", "descriptor", "next_slot"},
                f"invalid native checkpoint row for {name}")
        require(all(text(snapshot[key]) and SHA256.fullmatch(snapshot[key]) for key in hashes)
                and positive_integer(snapshot["xid"]) and positive_integer(snapshot["descriptor"]),
                f"invalid native checkpoint identity for {label}")
        require(all(isinstance(snapshot[key], list) and snapshot[key] and all(
            type(value) is int and value >= 0 for value in snapshot[key]) for key in rows)
            and type(snapshot["next_slot"]) is int and 0 <= snapshot["next_slot"] < bounds["descriptor_ring_slots"]
            and all(slot < bounds["descriptor_ring_slots"] for slot in snapshot["live_slots"]),
            f"invalid native ring slots or payload blocks for {label}")


def required_matrix(policy, registry, requested_profile):
    require(isinstance(policy, dict) and set(policy) == {"schema_version", "milestone", "profiles"}
            and type(policy["schema_version"]) is int and policy["schema_version"] == SCHEMA_VERSION,
            "invalid release policy schema")
    require(isinstance(registry, dict) and registry.get("project") == "apfs"
            and isinstance(registry.get("methods"), dict) and isinstance(registry.get("obligations"), list),
            "candidate does not have an APFS obligation registry")
    milestone = version(policy["milestone"])
    active = {}
    seen = set()
    for obligation in registry["obligations"]:
        require(isinstance(obligation, dict) and text(obligation.get("id")), "invalid obligation record")
        identifier = obligation["id"]
        require(identifier not in seen, f"duplicate obligation {identifier}")
        seen.add(identifier)
        activation = obligation["activation"]
        mandatory = obligation["mandatory_when_activated"]
        require(type(mandatory) is bool, f"invalid activation flag for {identifier}")
        if mandatory and activation not in UNSCHEDULED and activation_version(activation) <= milestone:
            methods = obligation["required_methods"]
            require(text_list(methods) and methods and len(set(methods)) == len(methods)
                    and set(methods) <= registry["methods"].keys(),
                    f"invalid required methods for {identifier}")
            active[identifier] = set(methods)
    require(active, "candidate has no active mandatory obligations")

    profiles = policy["profiles"]
    require(isinstance(profiles, dict), "invalid release policy profiles")
    covered = set()
    for name, profile in profiles.items():
        require(text(name) and isinstance(profile, dict) and PROFILE_FIELDS <= profile.keys(),
                f"invalid policy profile {name}")
        obligation, method = profile["obligation"], profile["method"]
        require(method in active.get(obligation, ()), f"inactive obligation or method in {name}")
        require(text_list(profile["features"]) and len(set(profile["features"])) == len(profile["features"])
                and text_list(profile["command"]) and profile["command"], f"invalid invocation for {name}")
        verify_method_policy(name, profile)
        if not profile.get("partial", False):
            covered.add((obligation, method))

    if requested_profile is not None:
        require(requested_profile in profiles, "unknown requested profile")
        return {requested_profile: profiles[requested_profile]}
    missing = {(obligation, method) for obligation, methods in active.items() for method in methods} - covered
    if missing:
        unconfigured = ", ".join(f"{obligation}/{method}" for obligation, method in sorted(missing))
        raise EvidenceError(f"release policy omits {unconfigured}")
    return profiles


def read_artifacts(root, artifacts):
    require(isinstance(artifacts, list) and artifacts, "invocation artifacts are missing")
    by_name = {}
    paths = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict) and set(artifact) == {"name", "sha256", "uri"}, "invalid artifact record")
        name, digest, uri = artifact["name"], artifact["sha256"], artifact["uri"]
        require(text(name) and name not in by_name and isinstance(digest, str) and SHA256.fullmatch(digest),
                "duplicate artifact or invalid SHA-256")
        require(text(uri) and "\\" not in uri and all(part not in {"", ".", ".."} for part in uri.split("/")),
                "artifact path must be relative to the evidence bundle")
        path = (root / uri).resolve(strict=True)
        require(path.is_file() and path.is_relative_to(root) and path not in paths,
                "artifact escapes the bundle or duplicates another path")
        paths.add(path)
        data = path.read_bytes()
        require(hashlib.sha256(data).hexdigest() == digest, f"artifact SHA-256 mismatch for {name}")
        by_name[name] = data
    require("transcript" in by_name, "invocation transcript is missing")
    return by_name["transcript"].decode("utf-8")


def validate_record(record, name, profile, commit, digest, artifacts_root):
    require(isinstance(record, dict) and RECORD_FIELDS <= record.keys()
            and record.keys() <= RECORD_FIELDS | OPTIONAL_RECORD_FIELDS, "invalid evidence record fields")
    require(type(record["schema_version"]) is int and record["schema_version"] == SCHEMA_VERSION
            and record["status"] == "pass" and record["dirty"] is False
            and type(record["exit_code"]) is int and record["exit_code"] == 0,
            "evidence must be a clean successful invocation")
    require(record["commit"] == commit and record["source_hash"] == digest,
            "stale evidence for a different Git commit or archive")
    require(record["profile"] == name and record["obligation_id"] == profile["obligation"]
            and record["method"] == profile["method"] and record["command"] == profile["command"],
            "invocation does not match profile")
    features = record["features"]
    require(text_list(features) and sorted(features) == sorted(profile["features"]),
            "features do not match profile")
    require(text_mapping(record["tool_versions"]) and all(
        record["tool_versions"].get(tool) == value for tool, value in profile["tool_versions"].items()
    ), "tool versions do not match profile")
    runner = record["runner"]
    require(text_mapping(runner) and {"os", "arch"} <= runner.keys() <= {"os", "arch", "hardware"}
            and text_list(record["assumptions"]) and positive_integer(record["duration_ms"]),
            "incomplete invocation provenance")
    require(json.dumps(record["bounds"], sort_keys=True) == json.dumps(profile["bounds"], sort_keys=True),
            "proof bounds do not match profile")
    proof = {"theorem": name} if profile["method"] in {"kani", "tlc"} else None
    if profile["method"] == "tlc":
        model = profile["model"]
        proof.update(states=model["states"], distinct_states=model["distinct_states"])
        require(record.get("seed") == str(profile["bounds"]["seed"]), "TLC seed does not match profile")
    if "locator_cases" in profile:
        require(record.get("seed") == str(profile["bounds"]["seed"]), "locator seed does not match profile")
    if "span_cases" in profile:
        require(record.get("seed") == str(profile["bounds"]["seed"]), "geometry span seed does not match profile")
    require((proof is None and "proof" not in record) or (proof is not None and record.get("proof") == proof),
            "proof metadata does not match profile")
    transcript = read_artifacts(artifacts_root, record["artifacts"])
    if profile["method"] == "kani":
        verify_kani(transcript, profile["harnesses"], profile["tool_versions"])
    elif profile["method"] == "tlc":
        verify_tlc(transcript, profile["model"], profile["bounds"], profile["tool_versions"])
    elif profile["method"] == "differential":
        if "geometry_cases" in profile:
            cases = profile["geometry_cases"]
            require(record.get("fixture_hash") == cases["ledger_sha256"],
                    "native geometry fixture hash does not match the acquisition ledger")
            verify_native_geometry(transcript, cases, profile["tool_versions"])
        else:
            verify_checksum_differential(transcript, profile["checksum_cases"], profile["bounds"], profile["tool_versions"])
    elif "locator_cases" in profile:
        verify_locator_properties(transcript, profile["locator_cases"], profile["bounds"], profile["tool_versions"])
    elif "span_cases" in profile:
        verify_span_properties(transcript, profile["span_cases"], profile["bounds"], profile["tool_versions"])
    elif "checkpoint_cases" in profile:
        verify_checkpoint_model(transcript, profile["checkpoint_cases"], profile["tool_versions"])
    elif "checkpoint_layouts" in profile:
        verify_checkpoint_layouts(transcript, profile["checkpoint_layouts"], profile["bounds"], profile["tool_versions"])
    elif profile["method"] == "native":
        if "native_checkpoints" in profile:
            fixtures = profile["native_checkpoints"]
            require(record.get("fixture_hash") == fixtures["ledger_set_sha256"],
                    "native fixture hash does not match the checkpoint acquisition ledgers")
            verify_native_checkpoints(transcript, fixtures, profile["bounds"], profile["tool_versions"])
        else:
            require(record.get("fixture_hash") == profile["native_fixture"]["ledger_sha256"],
                    "native fixture hash does not match the acquisition ledger")
            verify_native_bootstrap(transcript, profile["native_fixture"], profile["bounds"], profile["tool_versions"])
    else:
        verify_bootstrap_properties(transcript, profile["property_cases"], profile["tool_versions"])


def validate(root, bundle, requested_profile):
    root = root.resolve(strict=True)
    top = Path(git_output(root, "rev-parse", "--show-toplevel").decode().rstrip("\n")).resolve()
    require(top == root, "candidate argument must name the Git worktree root")
    status_args = ("status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=none")
    require(not git_output(root, *status_args), "candidate Git checkout has tracked or untracked changes")
    commit = git_output(root, "rev-parse", "HEAD").decode().strip()
    policy = parse_json(git_output(root, "show", f"{commit}:{POLICY_PATH}"))
    registry = parse_json(git_output(root, "show", f"{commit}:{REGISTRY_PATH}"))
    profiles = required_matrix(policy, registry, requested_profile)
    digest = archive_hash(root, commit)
    bundle = bundle.resolve(strict=True)
    records = parse_json(bundle.read_bytes())
    require(isinstance(records, list), "bundle must be a JSON array")
    pending = set(profiles)
    for record in records:
        require(isinstance(record, dict) and text(record.get("profile")), "invalid evidence profile field")
        name = record["profile"]
        require(name in pending, f"unexpected or duplicate evidence for {name}")
        try:
            validate_record(record, name, profiles[name], commit, digest, bundle.parent)
        except (ValueError, OSError) as error:
            raise EvidenceError(f"{name}: {error}") from error
        pending.remove(name)
    require(not pending, "missing evidence for " + ", ".join(sorted(pending)))
    require(not git_output(root, *status_args) and git_output(root, "rev-parse", "HEAD").decode().strip() == commit,
            "candidate Git checkout changed during validation")
    return len(profiles), policy["milestone"], commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="clean candidate checkout")
    parser.add_argument("--bundle", type=Path, required=True, help="schema v1 JSON array")
    parser.add_argument("--profile", help="check one invocation instead of all release evidence")
    arguments = parser.parse_args()
    try:
        count, milestone, commit = validate(arguments.root, arguments.bundle, arguments.profile)
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"Evidence rejected: {error}", file=sys.stderr)
        return 1
    if arguments.profile:
        print(f"Verified APFS {arguments.profile} invocation at {commit}. Release gate was not evaluated.")
    else:
        print(f"Verified {count} APFS evidence records for {milestone} at {commit}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
