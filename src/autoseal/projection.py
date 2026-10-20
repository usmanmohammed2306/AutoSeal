"""Checked artifact projection into a pristine local verifier workspace.

The check is appropriate for controlled local fixtures. It is not race-free
against a hostile process concurrently mutating the source or parent paths;
that requires an isolated provider with kernel-enforced filesystem controls.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Sequence


def safe_relative_artifact_path(path: str) -> bool:
    parts = path.split("/")
    return (
        bool(path)
        and not path.startswith("/")
        and "\\" not in path
        and "\x00" not in path
        and ":" not in path
        and all(part not in {"", ".", ".."} for part in parts)
        and PurePosixPath(path).as_posix() == path
    )


@dataclass(frozen=True)
class ProjectedArtifact:
    path: str
    sha256: str
    bytes_copied: int


@dataclass(frozen=True)
class ProjectionResult:
    artifacts: tuple[ProjectedArtifact, ...]
    identity: str


def _assert_no_symlink_ancestors(root: Path, relative: str) -> Path:
    if root.is_symlink():
        raise ValueError("projection root is a symlink")
    current = root
    for part in relative.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError(f"projection path contains a symlink: {relative}")
    return current


def project_candidate_artifacts(
    candidate: Path, destination: Path, allowed_files: Sequence[str],
) -> ProjectionResult:
    """Copy an allowlisted set without overwriting pristine verifier files."""

    names = tuple(allowed_files)
    if not names or len(set(names)) != len(names):
        raise ValueError("projection allowlist must be nonempty and unique")
    names = tuple(sorted(names))
    if any(not safe_relative_artifact_path(name) for name in names):
        raise ValueError("projection allowlist contains an unsafe relative path")
    if not candidate.is_dir() or not destination.is_dir():
        raise ValueError("candidate and destination must be directories")
    if candidate.is_symlink() or destination.is_symlink():
        raise ValueError("projection roots cannot be symlinks")

    sources: list[tuple[str, Path, Path]] = []
    for name in names:
        source = _assert_no_symlink_ancestors(candidate, name)
        target = _assert_no_symlink_ancestors(destination, name)
        try:
            mode = source.stat().st_mode
        except FileNotFoundError as exc:
            raise ValueError(f"allowlisted artifact is missing: {name}") from exc
        if not stat.S_ISREG(mode):
            raise ValueError(f"allowlisted artifact is not a regular file: {name}")
        if target.exists() or target.is_symlink():
            raise ValueError(f"projection would overwrite verifier content: {name}")
        for ancestor in target.parents:
            if ancestor == destination:
                break
            if ancestor.exists() and not ancestor.is_dir():
                raise ValueError(f"projection parent is not a directory: {name}")
        sources.append((name, source, target))

    copied: list[ProjectedArtifact] = []
    for name, source, target in sources:
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        source_fd = os.open(source, flags)
        with os.fdopen(source_fd, "rb") as source_file, target.open("xb") as target_file:
            while chunk := source_file.read(1024 * 1024):
                target_file.write(chunk)
                digest.update(chunk)
                size += len(chunk)
        copied.append(ProjectedArtifact(name, digest.hexdigest(), size))
    payload = json.dumps(
        [artifact.__dict__ for artifact in copied],
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    identity = "sha256:" + hashlib.sha256(b"autoseal.artifact-projection.v1\0" + payload).hexdigest()
    return ProjectionResult(tuple(copied), identity)
