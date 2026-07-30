#!/usr/bin/env python3
"""Генерирует public/version.json при сборке/деплое (CI).

Подключение в проекте (.gitlab-ci.yml, job загрузки):

    - python3 packages/leolnid/common-deploy/scripts/generate-version-json.py

В корне приложения нужен файл VERSION (semver: 0.1.0).
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def resolve_root() -> Path:
    if project_dir := env("CI_PROJECT_DIR"):
        return Path(project_dir)

    if app_root := env("APP_ROOT"):
        return Path(app_root)

    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "VERSION").is_file() or (parent / "artisan").is_file():
            return parent

    # packages/leolnid/common-deploy/scripts → корень приложения
    return here.parents[4]


ROOT = resolve_root()
VERSION_FILE = ROOT / "VERSION"
TARGET = ROOT / "public" / "version.json"


def main() -> int:
    raw_version = VERSION_FILE.read_text(encoding="utf-8").strip().lstrip("vV") if VERSION_FILE.is_file() else "0.0.0"
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", raw_version)
    if not match:
        print(f"Invalid VERSION format: {raw_version}", file=sys.stderr)
        return 1

    major, minor, patch = match.groups()
    version = f"v{major}.{minor}.{patch}"

    created_at = env("CI_PIPELINE_CREATED_AT") or datetime.now().astimezone().isoformat()
    build_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    version_build = f"{build_time.hour}h{build_time.minute:02d}m{build_time.second:02d}s"

    project_name = env("CI_PROJECT_NAME", "app")
    project_path = env("CI_PROJECT_PATH", "unknown/project")

    payload = {
        "version": version,
        "version_major": major,
        "version_minor": minor,
        "version_patch": patch,
        "version_build": version_build,
        "ci_project_name": project_name,
        "ci_project_path": project_path,
        "ci_pipeline_id": env("CI_PIPELINE_ID"),
        "ci_commit_sha": env("CI_COMMIT_SHA"),
        "ci_commit_branch": env("CI_COMMIT_REF_NAME"),
        "ci_commit_timestamp": env("CI_COMMIT_TIMESTAMP"),
    }

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(json.dumps(payload, ensure_ascii=False, indent=4) + "\n", encoding="utf-8")
    print(f"Wrote {TARGET} ({version}, build {version_build})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
