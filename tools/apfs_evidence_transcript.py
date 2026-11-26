"""Check invocation transcripts under the committed APFS evidence policy."""

import re
from collections import Counter
from hashlib import sha256


class EvidenceError(ValueError):
    """Evidence failed a release policy requirement."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


KANI_HARNESS = re.compile(r"^Checking harness (\S+)\.\.\.$", re.MULTILINE)
KANI_SUMMARY = "Manual Harness Summary:"
KANI_SUCCESS = "VERIFICATION:- SUCCESSFUL"
KANI_PROPERTIES = re.compile(r"\*\* (\d+) of (\d+) failed(?: \((\d+) unreachable\))?")
KANI_COVERS = re.compile(r"\*\* (\d+) of (\d+) cover properties satisfied")
TLC_BASELINE = "APFS TLC baseline"
TLC_WITNESS = "APFS TLC negative witness"
TLC_SUCCESS = "Model checking completed. No error has been found."
TLC_WITNESS_EXIT = "APFS TLC witness exit code: 12"
CHECKSUM_PREFIX = "APFS checksum "
CHECKSUM_SUCCESS = "APFS checksum differential completed"
NATIVE_GEOMETRY_PREFIX = "APFS native geometry "
NATIVE_GEOMETRY_SUCCESS = "APFS native geometry differential completed"
NATIVE_GEOMETRY_GROUPS = ("nxsb", "area", "map", "mapping")
BOOTSTRAP_PROPERTY_PREFIX = "APFS bootstrap property "
BOOTSTRAP_PROPERTY_SUCCESS = "APFS bootstrap properties completed"
NATIVE_BOOTSTRAP_PREFIX = "APFS native bootstrap "
NATIVE_BOOTSTRAP_SUCCESS = "APFS native bootstrap replay completed"
NATIVE_CHECKPOINT_PREFIX = "APFS native checkpoints "
NATIVE_CHECKPOINT_SUCCESS = "APFS native checkpoints replay completed"
CHECKPOINT_DIFFERENTIAL_PREFIX = "APFS checkpoint differential matched "
CHECKPOINT_DIFFERENTIAL_SUCCESS = "APFS checkpoint differential completed"
LOCATOR_PROPERTY_PREFIX = "APFS locator property "
LOCATOR_PROPERTY_SUCCESS = "APFS locator properties completed"
CHECKPOINT_MODEL_PREFIX = "APFS checkpoint model "
CHECKPOINT_MODEL_SUCCESS = "APFS checkpoint model completed"
CHECKPOINT_LAYOUT_PREFIX = "APFS checkpoint layout "
CHECKPOINT_LAYOUT_SUCCESS = "APFS checkpoint layouts completed"
STORED_CHECKSUM_BYTES = 8
FLETCHER_WORD_BYTES = 4


def verify_kani(transcript, harnesses, versions):
    lines = transcript.splitlines()
    require(lines.count(f"Kani Rust Verifier {versions['kani']} (cargo plugin)") == 1,
            "transcript has the wrong Kani version")
    require(f"CBMC {versions['cbmc']}" in lines, "transcript has the wrong CBMC version")
    results, sep, footer = transcript.partition(KANI_SUMMARY)
    count = len(harnesses)
    summary = f"Complete - {count} successfully verified harnesses, 0 failures, {count} total."
    require(sep and footer.splitlines().count(summary) == 1 and KANI_SUMMARY not in footer,
            "incomplete Kani summary")

    seen = set()
    blocks = KANI_HARNESS.split(results)
    for name, result in zip(blocks[1::2], blocks[2::2], strict=True):
        require(name in harnesses and name not in seen, f"unexpected Kani harness {name}")
        seen.add(name)
        lines = [line.strip() for line in result.splitlines()]
        require(lines.count(KANI_SUCCESS) == 1 and "VERIFICATION:- FAILED" not in lines,
                f"unsuccessful Kani harness {name}")
        properties = [match.groups() for line in lines if (match := KANI_PROPERTIES.fullmatch(line))]
        covers = [match.groups() for line in lines if (match := KANI_COVERS.fullmatch(line))]
        require(len(properties) == 1, f"missing or duplicate property result for {name}")
        failed, total, unreachable = properties[0]
        require(int(failed) == 0 and int(total) > int(unreachable or 0),
                f"failed or vacuous Kani properties for {name}")
        require(len(covers) == 1 and tuple(map(int, covers[0])) == (harnesses[name],) * 2,
                f"missing or unreached Kani covers for {name}")
    require(seen == set(harnesses), "missing required Kani harnesses")


def verify_tlc(transcript, model, bounds, versions):
    lines = transcript.splitlines()
    require(lines and lines[0] == TLC_BASELINE and lines.count(TLC_BASELINE) == 1
            and lines.count(TLC_WITNESS) == 1, "TLC baseline or negative witness is missing")
    boundary = lines.index(TLC_WITNESS)
    baseline, witness = lines[1:boundary], lines[boundary + 1:]
    for run in (baseline, witness):
        require(sum(line.startswith(f"TLC2 Version {versions['tlc']} of ") for line in run) == 1,
                "transcript has the wrong TLC version")
        workers = "worker" if bounds["workers"] == 1 else "workers"
        schedule = ("Running breadth-first search Model-Checking "
                    f"with fp {bounds['fingerprint_index']} and seed {bounds['seed']} "
                    f"with {bounds['workers']} {workers} on ")
        require(sum(line.startswith(schedule) and f" {versions['java']} " in line for line in run) == 1,
                "TLC schedule or Java runtime differs from policy")
        require(run.count(f"Semantic processing of module {model['name']}") == 1,
                "TLC transcript does not identify the required model")

    initial = f"Finished computing initial states: {model['initial_states']} distinct states generated at "
    temporal = ("Checking temporal properties for the complete state space with "
                f"{model['distinct_states']} total distinct states at ")
    states = (f"{model['states']} states generated, {model['distinct_states']} distinct states found, "
              "0 states left on queue.")
    depth = f"The depth of the complete state graph search is {model['depth']}."
    require(baseline.count(TLC_SUCCESS) == 1 and not any(line.startswith("Error:") for line in baseline),
            "TLC baseline did not complete successfully")
    require(sum(line.startswith(initial) for line in baseline) == 1 and baseline.count(states) == 1
            and baseline.count(depth) == 1, "TLC did not explore the complete bounded state graph")
    require(sum(line.startswith(temporal) for line in baseline) == 1
            and sum(line.startswith("Finished checking temporal properties in ") for line in baseline) == 1,
            "TLC temporal property check is incomplete")

    expected_error = f"Error: Invariant {model['violated_invariant']} is violated."
    require(TLC_SUCCESS not in witness and witness.count(expected_error) == 1 and witness[-1:] == [TLC_WITNESS_EXIT]
            and "Error: The behavior up to this point is:" in witness,
            "TLC negative witness did not produce the expected counterexample")


def verify_checksum_differential(transcript, cases, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "checksum transcript has the wrong Rust version")
    require(lines[-1:] == [CHECKSUM_SUCCESS] and lines.count(CHECKSUM_SUCCESS) == 1,
            "checksum differential run did not complete")

    expected = []
    for name, checksum in cases["fixtures"].items():
        expected.append(f"{CHECKSUM_PREFIX}native {name} {bounds['fixture_bytes']} {checksum}")
    for size in cases["block_sizes"]:
        positions = (STORED_CHECKSUM_BYTES, size // 2, size - FLETCHER_WORD_BYTES)
        for word in cases["uniform_words"]:
            expected.append(f"{CHECKSUM_PREFIX}uniform {size} {word}")
            for position in positions:
                expected.append(f"{CHECKSUM_PREFIX}singleton {size} {word} {position} {bounds['distinct_word']}")

    actual = Counter(line for line in lines[:-1] if line.startswith(CHECKSUM_PREFIX))
    expected = Counter(expected)
    require(actual == expected, "missing, duplicate, or unexpected checksum scenarios")


def verify_native_geometry(transcript, cases, versions):
    lines = transcript.splitlines()
    prefix = NATIVE_GEOMETRY_PREFIX
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "native geometry transcript has the wrong Rust version")
    require(lines[-1:] == [NATIVE_GEOMETRY_SUCCESS] and lines.count(NATIVE_GEOMETRY_SUCCESS) == 1,
            "native geometry differential run did not complete")
    rows = [line for line in lines[:-1] if line.startswith(prefix)]
    counts = cases["rows"]
    totals = " ".join(str(counts[group]) for group in NATIVE_GEOMETRY_GROUPS)
    for expected in [f"{prefix}ledger {cases['ledger_sha256']}",
                     f"{prefix}comparison {totals} {cases['rows_sha256']}"]:
        require(rows.count(expected) == 1, "native geometry ledger or comparison does not match policy")
        rows.remove(expected)
    require(Counter(line[len(prefix):].partition(" ")[0] for line in rows) == Counter(counts),
            "native geometry row counts do not match policy")
    digest = sha256("\n".join(sorted(rows)).encode("ascii")).hexdigest()
    require(digest == cases["rows_sha256"], "native geometry rows do not match the independent comparison")


def verify_bootstrap_properties(transcript, cases, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "bootstrap property transcript has the wrong Rust version")
    require(lines[-1:] == [BOOTSTRAP_PROPERTY_SUCCESS] and lines.count(BOOTSTRAP_PROPERTY_SUCCESS) == 1,
            "bootstrap property run did not complete")
    expected = Counter(f"{BOOTSTRAP_PROPERTY_PREFIX}{case} {' '.join(map(str, values))}"
                       for case, rows in cases.items() for values in rows)
    actual = Counter(line for line in lines if line.startswith(BOOTSTRAP_PROPERTY_PREFIX))
    require(actual == expected, "missing, duplicate, or unexpected bootstrap property scenarios")


def verify_locator_properties(transcript, cases, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1
            and lines.count(f"proptest v{versions['proptest']}") == 1,
            "locator transcript has the wrong tool versions")
    require(lines.count(f"APFS locator seed {bounds['seed']}") == 1, "wrong locator property seed")
    require(lines[-1:] == [LOCATOR_PROPERTY_SUCCESS] and lines.count(LOCATOR_PROPERTY_SUCCESS) == 1,
            "locator property run did not complete")
    expected = Counter(f"{LOCATOR_PROPERTY_PREFIX}{layout} {size} {scenario} {bounds['cases_per_scenario']}"
                       for layout in cases["layouts"] for size in cases["block_sizes"]
                       for scenario in cases["scenarios"])
    actual = Counter(line for line in lines if line.startswith(LOCATOR_PROPERTY_PREFIX))
    require(actual == expected, "missing, duplicate, or unexpected locator property scenarios")


def verify_span_properties(transcript, cases, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1
            and lines.count(f"proptest v{versions['proptest']}") == 1,
            "span transcript has the wrong tool versions")
    require(lines.count(f"APFS span seed {bounds['seed']}") == 1, "wrong span property seed")
    completion = "APFS span properties completed"
    require(lines[-1:] == [completion] and lines.count(completion) == 1, "span property run did not complete")
    prefix = "APFS span property "
    runs = bounds["cases_per_shape"]
    paths = Counter(f"{prefix}{profile} {size} {entries} {runs} {(entries + bounds['boundary_ranges']) * runs}"
                    for profile, sizes in cases.items() for size in sizes
                    for entries in range(bounds["max_entries"] + 1))
    require(Counter(line for line in lines if line.startswith(prefix)) == paths,
            "missing, duplicate, or unexpected span property scenarios")


def verify_native_windows(transcript, fixtures, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "native window transcript has the wrong Rust version")
    completion = "APFS native windows completed"
    require(lines[-1:] == [completion] and lines.count(completion) == 1, "native windows did not complete")
    prefix = "APFS native window "
    size = bounds["object_bytes"]
    windows = (size - bounds["minimum_prefix_bytes"]) // bounds["word_bytes"] + 1
    expected = Counter(f"{prefix}{name} {size} {windows} {checksum}" for name, checksum in fixtures.items())
    require(Counter(line for line in lines if line.startswith(prefix)) == expected,
            "missing, duplicate, or unexpected native window scenarios")


def verify_complete_objects(transcript, sizes, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1
            and lines.count(f"proptest v{versions['proptest']}") == 1,
            "complete object transcript has the wrong tool versions")
    require(lines.count(f"APFS complete object seed {bounds['seed']}") == 1, "wrong complete object property seed")
    completion = "APFS complete object properties completed"
    require(lines[-1:] == [completion] and lines.count(completion) == 1, "complete object property run did not complete")
    prefix = "APFS complete object property "
    count = bounds["cases_per_block_size"]
    windows = count * bounds["checksum_windows_per_object"]
    ranges = count * bounds["byte_ranges_per_object"]
    profiles = count * bounds["compatible_profiles_per_object"]
    expected = Counter(f"{prefix}{size} {count} {windows} {ranges} {profiles}" for size in sizes)
    require(Counter(line for line in lines if line.startswith(prefix)) == expected,
            "missing, duplicate, or unexpected complete object property scenarios")


def verify_checkpoint_model(transcript, cases, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "checkpoint model transcript has the wrong Rust version")
    require(lines[-1:] == [CHECKPOINT_MODEL_SUCCESS] and lines.count(CHECKPOINT_MODEL_SUCCESS) == 1,
            "checkpoint model run did not complete")
    expected = Counter(f"{CHECKPOINT_MODEL_PREFIX}{early} {latest} {request}"
                       for early in cases["states"] for latest in cases["states"]
                       for request in cases["requests"])
    actual = Counter(line for line in lines[:-1] if line.startswith(CHECKPOINT_MODEL_PREFIX))
    require(actual == expected, "missing, duplicate, or unexpected checkpoint model scenarios")


def verify_checkpoint_layouts(transcript, matrix, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "checkpoint layouts transcript has the wrong Rust version")
    require(lines[-1:] == [CHECKPOINT_LAYOUT_SUCCESS] and lines.count(CHECKPOINT_LAYOUT_SUCCESS) == 1,
            "checkpoint layouts run did not complete")
    expected = Counter()
    for slots in matrix["ring_slots"]:
        for count in matrix["candidate_counts"]:
            orders = matrix["orders"][:1] if count == 1 else matrix["orders"]
            requests = ["automatic", *map(str, range(bounds["first_xid"], bounds["first_xid"] + count))]
            expected.update(f"{CHECKPOINT_LAYOUT_PREFIX}{slots} {count} {placement} {order} {request}"
                            for placement in matrix["placements"] for order in orders for request in requests)
    require(expected.total() == bounds["cases"], "checkpoint layout matrix disagrees with the case bound")
    actual = Counter(line for line in lines if line.startswith(CHECKPOINT_LAYOUT_PREFIX))
    require(actual == expected, "missing, duplicate, or unexpected checkpoint layout cases")


def verify_native_bootstrap(transcript, fixture, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "native bootstrap transcript has the wrong Rust version")
    require(lines[-1:] == [NATIVE_BOOTSTRAP_SUCCESS] and lines.count(NATIVE_BOOTSTRAP_SUCCESS) == 1,
            "native bootstrap replay did not complete")
    expected = [
        f"ledger {fixture['ledger_sha256']}",
        f"oracle {fixture['os_version']} {fixture['os_build']} {fixture['architecture']} "
        f"{fixture['oracle_version']} 0 {fixture['checkpoint_xid']} {fixture['raw_sha256']}",
        f"fixture {fixture['metadata_sha256']} {fixture['bootstrap_sha256']} {fixture['fsroot_sha256']}",
        f"admitted {bounds['block_count'] * bounds['block_bytes']} {bounds['block_bytes']} "
        f"{bounds['block_count']} {fixture['checkpoint_xid']} {fixture['wire_checksum']} {bounds['admitted_reads']}",
        *(f"refused {case} {reads}" for case, reads in bounds["refused_reads"].items()),
    ]
    actual = Counter(line for line in lines[:-1] if line.startswith(NATIVE_BOOTSTRAP_PREFIX))
    require(actual == Counter(f"{NATIVE_BOOTSTRAP_PREFIX}{row}" for row in expected),
            "native bootstrap ledger, fixture, or replay facts disagree with the policy")


def checkpoint_replay_facts(name, snapshot, slots):
    return (f"{name} {snapshot['xid']} {snapshot['descriptor']} {slots} {snapshot['next_slot']} "
            f"{snapshot['live_slots']} {snapshot['descriptor_xids']} {snapshot['payload_blocks']}")


def verify_native_checkpoints(transcript, fixtures, bounds, versions):
    lines = transcript.splitlines()
    require(sum(line.startswith(f"rustc {versions['rustc']} (") for line in lines) == 1,
            "native checkpoint transcript has the wrong Rust version")
    require(lines[-1:] == [NATIVE_CHECKPOINT_SUCCESS] and lines.count(NATIVE_CHECKPOINT_SUCCESS) == 1,
            "native checkpoint replay did not complete")
    expected = [f"ledgers {fixtures['ledger_set_sha256']}"]
    for name, snapshot in fixtures["snapshots"].items():
        expected.extend([
            f"fixture {name} {snapshot['ledger_sha256']} {snapshot['packed_sha256']} {snapshot['raw_sha256']}",
            f"oracle {name} {fixtures['os_version']} {fixtures['os_build']} {fixtures['architecture']} "
            f"{fixtures['oracle_version']} 0 {snapshot['xid']}",
            f"replay {checkpoint_replay_facts(name, snapshot, bounds['descriptor_ring_slots'])}",
        ])
    actual = Counter(line for line in lines[:-1] if line.startswith(NATIVE_CHECKPOINT_PREFIX))
    require(actual == Counter(f"{NATIVE_CHECKPOINT_PREFIX}{row}" for row in expected),
            "native checkpoint ledgers, fixture digests, or observed selection disagree with the policy")


def verify_checkpoint_differential(transcript, fixtures, bounds, versions):
    lines = transcript.splitlines()
    require(lines[-1:] == [CHECKPOINT_DIFFERENTIAL_SUCCESS] and lines.count(CHECKPOINT_DIFFERENTIAL_SUCCESS) == 1,
            "checkpoint differential did not complete")
    require(lines.count(NATIVE_CHECKPOINT_SUCCESS) == 1, "expected one native production replay")
    boundary = lines.index(NATIVE_CHECKPOINT_SUCCESS)
    verify_native_checkpoints("\n".join(lines[:boundary + 1]), fixtures, bounds, versions)
    expected = Counter(f"{CHECKPOINT_DIFFERENTIAL_PREFIX}"
                       f"{checkpoint_replay_facts(name, snapshot, bounds['descriptor_ring_slots'])}"
                       for name, snapshot in fixtures["snapshots"].items())
    require(Counter(lines[boundary + 1:-1]) == expected,
            "missing or inconsistent independent checkpoint comparisons")
