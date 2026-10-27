"""Safely extract the checksum-pinned cloudflared source archive for SBOM builds."""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

EXPECTED_ROOT = "cloudflared-002a5ccaf75a4e612bfa451063c1d82a2d13336b"

# Bazel's Python launcher can omit the script directory from sys.path. Load the
# declared sibling helper by its exact path instead of ambient import search.
VENDOR_HELPER = Path(__file__).with_name("extract_sbom_vendor.py")
vendor_spec = importlib.util.spec_from_file_location("extract_sbom_vendor", VENDOR_HELPER)
if vendor_spec is None or vendor_spec.loader is None:
    raise RuntimeError(f"could not load vendor archive helper: {VENDOR_HELPER}")
vendor_helper = importlib.util.module_from_spec(vendor_spec)
vendor_spec.loader.exec_module(vendor_helper)
VendorArchiveError = vendor_helper.VendorArchiveError
extract_vendor_archive = vendor_helper.extract_archive
tree_digest = vendor_helper.tree_digest


class CloudflaredArchiveError(RuntimeError):
    pass


def fail(message: str) -> CloudflaredArchiveError:
    return CloudflaredArchiveError(message)


def require_test_tmpdir_child(raw_path: str) -> Path:
    output_root = Path(raw_path)
    if not output_root.is_absolute():
        raise fail("--output-root must be absolute")
    test_tmpdir = os.environ.get("TEST_TMPDIR")
    if not os.environ.get("BAZEL_TEST") or not test_tmpdir:
        raise fail("BAZEL_TEST and TEST_TMPDIR are required")
    test_root = Path(test_tmpdir)
    if not test_root.is_absolute():
        raise fail("TEST_TMPDIR must be absolute")
    resolved_test_root = test_root.resolve(strict=True)
    resolved_parent = output_root.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(resolved_test_root)
    except ValueError as error:
        raise fail("--output-root must stay below TEST_TMPDIR") from error
    if ".." in output_root.parts:
        raise fail("--output-root must not use non-canonical paths")
    return output_root


def safe_member_path(member_name: str) -> PurePosixPath:
    raw_parts = member_name.split("/")
    if member_name.startswith("/") or "." in raw_parts or ".." in raw_parts:
        raise fail(f"cloudflared archive has an unsafe path: {member_name}")
    path = PurePosixPath(member_name)
    if path.is_absolute() or not path.parts or path.parts[0] != EXPECTED_ROOT:
        raise fail(f"cloudflared archive has an unexpected path: {member_name}")
    return path


def expected_vendor_digest(path: Path) -> str:
    if not path.is_absolute() or not path.is_file():
        raise fail("--vendor-digest must be an absolute file")
    digest = path.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise fail("--vendor-digest must contain one lowercase SHA256 digest")
    return digest


def extract_archive(
    archive: Path, vendor_archive: Path, vendor_digest: Path, output_root: Path
) -> Path:
    if not archive.is_absolute() or not archive.is_file():
        raise fail("--archive must be an absolute file")
    if output_root.exists() or output_root.is_symlink():
        raise fail("cloudflared output root already exists")
    expected_digest = expected_vendor_digest(vendor_digest)

    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if not members:
            raise fail("cloudflared archive is empty")
        seen_paths: set[PurePosixPath] = set()
        file_paths: set[PurePosixPath] = set()
        for member in members:
            member_path = safe_member_path(member.name)
            if len(member_path.parts) > 1 and member_path.parts[1] == "vendor":
                raise fail("cloudflared source archive must not contain a vendor tree")
            if member_path in seen_paths:
                raise fail(f"cloudflared archive has a duplicate path: {member.name}")
            seen_paths.add(member_path)
            if member.issym() or member.islnk():
                raise fail(f"cloudflared archive must not contain links: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise fail(f"cloudflared archive has an unsupported entry: {member.name}")
            if len(member_path.parts) == 1 and not member.isdir():
                raise fail("cloudflared archive root must be a directory")
            if member.isfile():
                file_paths.add(member_path)
        for member_path in seen_paths:
            for index in range(1, len(member_path.parts)):
                ancestor = PurePosixPath(*member_path.parts[:index])
                if ancestor in file_paths:
                    raise fail(
                        "cloudflared archive has a file/directory conflict: "
                        f"{ancestor} is a parent of {member_path}"
                    )
        for member in members:
            member_path = safe_member_path(member.name)
            destination = output_root.joinpath(*member_path.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            extracted = source.extractfile(member)
            if extracted is None:
                raise fail(f"could not extract cloudflared archive file: {member.name}")
            with extracted, destination.open("xb") as output:
                shutil.copyfileobj(extracted, output)
            destination.chmod(member.mode & 0o777)

    source_root = output_root / EXPECTED_ROOT
    for relative_path in ("go.mod", "cmd/cloudflared/main.go"):
        if not (source_root / relative_path).is_file():
            raise fail(f"cloudflared source is missing {relative_path}")
    extract_vendor_archive(source_root, vendor_archive)
    actual_digest = tree_digest(source_root / "vendor")
    if actual_digest != expected_digest:
        raise fail(
            f"cloudflared vendor tree digest mismatch: got {actual_digest}, want {expected_digest}"
        )
    return source_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--vendor-archive", required=True)
    parser.add_argument("--vendor-digest", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    try:
        output_root = require_test_tmpdir_child(args.output_root)
        source_root = extract_archive(
            Path(args.archive),
            Path(args.vendor_archive),
            Path(args.vendor_digest),
            output_root,
        )
    except (CloudflaredArchiveError, VendorArchiveError, OSError, tarfile.TarError) as error:
        print(f"extract_sbom_cloudflared.py: {error}", file=sys.stderr)
        return 1
    print(source_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
