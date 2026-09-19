"""
Artifact extractor — unpacks archives before scanning.
Supports: .tar.gz, .tgz, .zip, .whl (wheel = zip), .tar.bz2
Falls back to writing raw bytes as a single file for unknown types.

Returns the path to the extracted directory.
"""

import os
import tarfile
import zipfile
from pathlib import Path


def extract(data: bytes, source_url: str, dest_dir: str) -> str:
    """
    Write and extract artifact bytes into dest_dir.
    Returns the path that scanners should scan (always dest_dir).
    """
    url_lower = source_url.lower().split("?")[0]  # strip query params
    dest = Path(dest_dir)

    if url_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        try:
            _extract_tar(data, dest)
        except Exception:
            _write_raw(data, source_url, dest)
    elif url_lower.endswith((".zip", ".whl")):
        try:
            _extract_zip(data, dest)
        except Exception:
            _write_raw(data, source_url, dest)
    else:
        # Unknown type — write as-is and let scanners handle it
        _write_raw(data, source_url, dest)

    return dest_dir


def detect_languages(artifact_dir: str) -> set[str]:
    """
    Walk the extracted directory and return the set of languages present.
    Used to decide which scanners to run.
    """
    languages: set[str] = set()
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".rb": "ruby",
        ".java": "java",
        ".sh": "shell",
        ".bash": "shell",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
    }
    for root, _, files in os.walk(artifact_dir):
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext in ext_map:
                languages.add(ext_map[ext])
    return languages


def has_requirements(artifact_dir: str) -> bool:
    """True if the artifact has any dependency declaration file."""
    markers = (
        "requirements.txt", "requirements-dev.txt", "setup.py",
        "setup.cfg", "pyproject.toml", "Pipfile",
    )
    base = Path(artifact_dir)
    for root, _, files in os.walk(str(base)):
        for f in files:
            if f in markers:
                return True
    return False


def _extract_tar(data: bytes, dest: Path) -> None:
    import io
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        # Security: strip absolute paths and path traversal
        members = []
        for m in tf.getmembers():
            m.name = _safe_path(m.name)
            if m.name:
                members.append(m)
        tf.extractall(path=str(dest), members=members)


def _extract_zip(data: bytes, dest: Path) -> None:
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            safe = _safe_path(info.filename)
            if not safe:
                continue
            target = dest / safe
            target.parent.mkdir(parents=True, exist_ok=True)
            if not info.is_dir():
                target.write_bytes(zf.read(info.filename))


def _write_raw(data: bytes, source_url: str, dest: Path) -> None:
    from urllib.parse import urlparse
    filename = urlparse(source_url).path.split("/")[-1] or "artifact"
    (dest / filename).write_bytes(data)


def _safe_path(path: str) -> str:
    """Strip leading slashes and path traversal components."""
    parts = [p for p in Path(path).parts if p not in ("", ".", "..") and not p.startswith("/")]
    return str(Path(*parts)) if parts else ""
