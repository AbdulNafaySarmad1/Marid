"""Verify downloaded MARID export files without a MARID account or dependencies."""

import argparse
import hashlib
import json
import re
from pathlib import Path

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def digest(path: Path) -> tuple[int, str, int]:
    size = rows = 0
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            size += len(block)
            rows += block.count(b"\n")
            hasher.update(block)
    return size, hasher.hexdigest(), rows


def verify_bundle(manifest_path: Path, directory: Path,
                  expected_manifest_sha256: str | None = None) -> int:
    manifest_path = manifest_path.resolve(strict=True)
    directory = directory.resolve(strict=True)
    if expected_manifest_sha256 is not None:
        if not SHA256.fullmatch(expected_manifest_sha256):
            raise ValueError("Expected manifest SHA-256 must be lowercase hexadecimal.")
        if digest(manifest_path)[1] != expected_manifest_sha256:
            raise ValueError("Manifest SHA-256 does not match the trusted value.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("artifacts"), list):
        raise ValueError("Unsupported manifest schema.")
    seen = set()
    for item in manifest["artifacts"]:
        name = item.get("name")
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in seen:
            raise ValueError("Invalid or duplicate artifact name.")
        seen.add(name)
        target = directory / name
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"Missing or unsafe artifact: {name}")
        size, actual, rows = digest(target)
        if (size != item.get("byteSize") or actual != item.get("sha256") or
                (name.endswith(".ndjson") and rows != item.get("rowCount"))):
            raise ValueError(f"Artifact failed verification: {name}")
    return len(seen)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("directory", type=Path,
                        help="Directory containing files named in the manifest")
    parser.add_argument("--expected-manifest-sha256",
                        help="Trusted SHA-256 from a separate channel")
    args = parser.parse_args()
    try:
        count = verify_bundle(args.manifest, args.directory,
                              args.expected_manifest_sha256)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Verification failed: {error}\n")
    print(f"Verified {count} artifacts and their SHA-256 hashes.")
    if args.expected_manifest_sha256 is None:
        print("Manifest origin is unverified; provide a trusted manifest hash or signature.")
