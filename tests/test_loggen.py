import json
from pathlib import Path

from pam_copilot.kb import load_runbooks
from pam_copilot.loggen import CATALOG, generate, main

SECRET_TYPES = {"password", "token", "api_key"}


def test_catalog_and_runbooks_agree() -> None:
    runbooks = {rb.id: rb for rb in load_runbooks()}
    for spec in CATALOG:
        assert spec.code in runbooks[spec.runbook_id].error_codes, spec.code
    documented = {code for rb in runbooks.values() for code in rb.error_codes}
    assert documented == {spec.code for spec in CATALOG}


def test_deterministic_with_seed() -> None:
    assert generate(10, seed=7, with_secrets=True) == generate(10, seed=7, with_secrets=True)


def test_every_code_renders_and_is_labeled() -> None:
    samples = generate(len(CATALOG), seed=1, with_secrets=True)
    assert {s.error_code for s in samples} == {spec.code for spec in CATALOG}
    for s in samples:
        assert s.simulated
        assert f"{s.error_code}: " in s.log
        assert "{" not in s.log  # no unrendered template fields
        assert SECRET_TYPES & {item["type"] for item in s.sensitive}, s.id
        assert all(item["value"] in s.log for item in s.sensitive)


def test_no_secrets_unless_requested() -> None:
    for s in generate(len(CATALOG), seed=2):
        assert not SECRET_TYPES & {item["type"] for item in s.sensitive}, s.id


def test_code_prefix_filter() -> None:
    assert {s.component for s in generate(10, seed=3, code_prefix="sim-psm")} == {"PSM"}


def test_cli_writes_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "logs.jsonl"
    main(["-n", "3", "--seed", "1", "--jsonl", str(out)])
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 3
    assert all(row["simulated"] is True for row in rows)
