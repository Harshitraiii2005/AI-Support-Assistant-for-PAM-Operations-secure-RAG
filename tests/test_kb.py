from pathlib import Path

import pytest

from pam_copilot.kb import load_runbooks, parse_runbook


def test_runbooks_load_with_unique_ids() -> None:
    runbooks = load_runbooks()
    assert 15 <= len(runbooks) <= 20
    assert len({rb.id for rb in runbooks}) == len(runbooks)
    assert all(rb.body.startswith("# ") for rb in runbooks)


def test_filename_starts_with_runbook_id() -> None:
    for rb in load_runbooks():
        assert rb.path.name.startswith(rb.id + "-"), rb.path.name


@pytest.mark.parametrize(
    "header",
    [
        "id: RB-999\ntitle: x\ncomponent: CPM\naudience: root\nlast_updated: 2026-01-01\n"
        "error_codes: []\ntags: []",
        "id: RB-999\ntitle: x\ncomponent: CPM\naudience: operator\nlast_updated: yesterday\n"
        "error_codes: []\ntags: []",
        "id: RB-999\ntitle: x",
        "!!python/object/apply:os.system ['echo pwned']",
    ],
)
def test_invalid_front_matter_rejected(tmp_path: Path, header: str) -> None:
    path = tmp_path / "RB-999-bad.md"
    path.write_text(f"---\n{header}\n---\n# Bad\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_runbook(path)
