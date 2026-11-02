"""Validates the reports the integration tests wrote.

Every SARIF file must validate against the SARIF 2.1.0 schema, every JUnit
file must be well-formed with counts that match its test cases, and every
run record must validate against schemas/run-record.v1.json. Each kind must
turn up at least once, so a job that stopped writing reports fails here too.

Usage:
    python3 tests/validate_reports.py --sarif-schema SCHEMA [--kinds KIND,...] DIR...

--kinds names the kinds that must turn up (default sarif,junit,record), for a
job whose commands write no SARIF.

Needs jsonschema (pip install jsonschema).
"""

import argparse
import json
import pathlib
import sys
import xml.etree.ElementTree as ElementTree

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parent.parent


def errors_against(validator, path):
    document = json.loads(path.read_text(encoding="utf-8"))
    return [
        f"{'/'.join(map(str, error.absolute_path)) or '(root)'}: {error.message[:300]}"
        for error in validator.iter_errors(document)
    ]


def junit_errors(path):
    try:
        root = ElementTree.parse(path).getroot()
    except ElementTree.ParseError as error:
        return [f"not well-formed XML: {error}"]
    if root.tag != "testsuites":
        return [f"the root element is <{root.tag}>, not <testsuites>"]
    problems = []
    for suite in root.iter("testsuite"):
        cases = suite.findall("testcase")
        counts = {
            "tests": len(cases),
            "failures": sum(1 for case in cases if case.find("failure") is not None),
            "skipped": sum(1 for case in cases if case.find("skipped") is not None),
        }
        for name, count in counts.items():
            if suite.get(name) != str(count):
                problems.append(f"testsuite {suite.get('name')}: {name}=\"{suite.get(name)}\", but it has {count}")
        if not cases:
            problems.append(f"testsuite {suite.get('name')} has no test cases")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sarif-schema", required=True, type=pathlib.Path)
    parser.add_argument("--kinds", default="sarif,junit,record")
    parser.add_argument("dirs", nargs="+", type=pathlib.Path)
    args = parser.parse_args()

    sarif_schema = json.loads(args.sarif_schema.read_text(encoding="utf-8"))
    sarif = jsonschema.Draft4Validator(sarif_schema)
    record_schema = json.loads((ROOT / "schemas" / "run-record.v1.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(record_schema)
    record = jsonschema.Draft202012Validator(record_schema)

    checks = {
        "SARIF": ("sarif", "*.sarif", lambda path: errors_against(sarif, path)),
        "JUnit": ("junit", "junit/*.xml", junit_errors),
        "run record": ("record", "*.run-record.json", lambda path: errors_against(record, path)),
    }
    required = set(args.kinds.split(","))
    failures = 0
    for kind, (key, pattern, check) in checks.items():
        files = sorted({path for directory in args.dirs for path in directory.rglob(pattern)})
        if not files and key not in required:
            continue
        if not files:
            print(f"FAIL: no {kind} files under {', '.join(map(str, args.dirs))}")
            failures += 1
            continue
        for path in files:
            problems = check(path)
            for problem in problems:
                print(f"FAIL: {path}: {problem}")
            failures += bool(problems)
        print(f"checked {len(files)} {kind} files")
    if failures:
        print(f"{failures} problem(s)")
        return 1
    print("ok: every report is valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
