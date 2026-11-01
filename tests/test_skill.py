"""The agent skill must follow the Agent Skills spec so every agent loads it."""

import re
from pathlib import Path

SKILL_DIR = Path(__file__).parent.parent / "skills" / "soc-shift-handoff"
SKILL_MD = SKILL_DIR / "SKILL.md"


def _frontmatter():
    text = SKILL_MD.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert m, "SKILL.md must start with --- frontmatter ---"
    head, body = m.groups()
    fields = dict(re.findall(r"^([a-z_-]+):\s*(.*)$", head, re.M))
    return fields, body


def test_name_matches_folder_and_rules():
    fields, _ = _frontmatter()
    name = fields["name"]
    assert name == SKILL_DIR.name
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and len(name) <= 64


def test_description_present_and_short():
    fields, _ = _frontmatter()
    assert 50 < len(fields["description"]) <= 1024


def test_only_portable_top_level_fields():
    fields, _ = _frontmatter()
    allowed = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
    assert set(fields) <= allowed, set(fields) - allowed


def test_body_under_500_lines():
    _, body = _frontmatter()
    assert len(body.splitlines()) < 500


def test_referenced_files_exist():
    _, body = _frontmatter()
    for ref in re.findall(r"`((?:references|scripts)/[\w.-]+)`", body):
        assert (SKILL_DIR / ref).exists(), ref
