#!/usr/bin/env python3
"""Regenerate the OFFICIAL_RUNTIMES table in crates/urt-executor/src/config.rs.

Queries the public Docker Hub tag listing for every openruntimes/<family>
repository, keeps the v5 tags, orders them newest-first and prints the Rust
literal for the table together with a refreshed "verified against Docker Hub"
comment.

Usage:
    python scripts/refresh-runtime-table.py            # print the Rust table
    python scripts/refresh-runtime-table.py --json     # print the raw tag data

The output is meant to be pasted over the existing OFFICIAL_RUNTIMES constant.
Nothing is written to disk and no images are pulled.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

FAMILIES = [
    "bun",
    "cpp",
    "dart",
    "deno",
    "dotnet",
    "flutter",
    "go",
    "java",
    "kotlin",
    "node",
    "php",
    "python",
    "python-ml",
    "ruby",
    "rust",
    "static",
    "swift",
]

TAG_ENDPOINT = "https://hub.docker.com/v2/repositories/openruntimes/{family}/tags?page_size=100"
V5_TAG = re.compile(r"^v5-(\d+(?:\.\d+)*)$")


def fetch_tags(family: str) -> list[str]:
    """Return every tag name published for openruntimes/<family>."""
    url = TAG_ENDPOINT.format(family=family)
    names: list[str] = []
    while url:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
        names.extend(tag["name"] for tag in payload.get("results", []))
        url = payload.get("next")
    return names


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def v5_versions(tags: list[str]) -> list[str]:
    """v5 versions for a family, newest first."""
    versions = {match.group(1) for match in map(V5_TAG.match, tags) if match}
    return sorted(versions, key=version_key, reverse=True)


def collect() -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}
    for family in FAMILIES:
        try:
            tags = fetch_tags(family)
        except urllib.error.HTTPError as error:
            print(f"{family}: HTTP {error.code}", file=sys.stderr)
            continue
        versions = v5_versions(tags)
        if not versions:
            print(f"{family}: no v5 tags found", file=sys.stderr)
            continue
        table[family] = versions
    return table


def render_rust(table: dict[str, list[str]]) -> str:
    today = datetime.now(timezone.utc).date().isoformat()
    lines = [
        f"// Verified against Docker Hub on {today}.",
        "const OFFICIAL_RUNTIMES: &[OfficialRuntime] = &[",
    ]
    for family, versions in table.items():
        rendered = ", ".join(f'"{version}"' for version in versions)
        lines.append("    OfficialRuntime {")
        lines.append(f'        family: "{family}",')
        lines.append(f'        versions: &[{rendered}],')
        lines.append("    },")
    lines.append("];")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print raw JSON instead of Rust")
    args = parser.parse_args()

    table = collect()
    if not table:
        return 1

    if args.json:
        json.dump(table, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_rust(table))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
