from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    return [
        REPO_ROOT / "README.md",
        *sorted((REPO_ROOT / "docs").rglob("*.md")),
        *sorted((REPO_ROOT / "demos").rglob("*.md")),
    ]


def _local_target(raw_target: str) -> str | None:
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None
    if target.startswith(("http://", "https://", "mailto:")):
        return None
    if " " in target:
        target = target.split(" ", 1)[0]
    return target.split("#", 1)[0]


def test_public_markdown_local_links_point_to_existing_paths() -> None:
    missing_links: list[str] = []

    for markdown_path in _markdown_files():
        text = markdown_path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_RE.finditer(text):
            target = _local_target(match.group(1))
            if target is None:
                continue

            resolved = (markdown_path.parent / target).resolve()
            try:
                resolved.relative_to(REPO_ROOT.resolve())
            except ValueError:
                missing_links.append(
                    f"{markdown_path.relative_to(REPO_ROOT)} links outside repo: {target}"
                )
                continue

            if not resolved.exists():
                missing_links.append(
                    f"{markdown_path.relative_to(REPO_ROOT)} -> {target}"
                )

    assert missing_links == []
