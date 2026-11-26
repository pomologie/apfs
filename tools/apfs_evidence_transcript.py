"""Check invocation transcripts under the committed APFS evidence policy."""

import re
from collections import Counter


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
