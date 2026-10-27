from __future__ import annotations

import io
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("extract_sbom_cloudflared.py")
ROOT = "cloudflared-002a5ccaf75a4e612bfa451063c1d82a2d13336b"
# Tree digest for a vendor archive containing only modules.txt with "# vendor\n".
VENDOR_DIGEST = "1b69de676deaae582b5036191554bfce6cc86e1bb3537bc7acb5ef5ee15e78a1"


class ExtractSbomCloudflaredTest(unittest.TestCase):
    def add_file(self, archive: tarfile.TarFile, name: str, contents: bytes) -> None:
        member = tarfile.TarInfo(name)
        member.size = len(contents)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(contents))

    def make_archive(
        self,
        root: pathlib.Path,
        extra_members: list[tuple[tarfile.TarInfo, bytes | None]] | None = None,
    ) -> pathlib.Path:
        archive_path = root / "cloudflared.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            self.add_file(archive, f"{ROOT}/go.mod", b"module github.com/cloudflare/cloudflared\n")
            self.add_file(
                archive,
                f"{ROOT}/cmd/cloudflared/main.go",
                b"package main\n",
            )
            for member, contents in extra_members or []:
                archive.addfile(member, io.BytesIO(contents) if contents is not None else None)
        return archive_path

    def make_vendor_archive(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        digest_path = root / "vendor.sha256"
        digest_path.write_text(VENDOR_DIGEST + "\n", encoding="utf-8")
        archive_path = root / "vendor.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            self.add_file(archive, "vendor/modules.txt", b"# vendor\n")
        return archive_path, digest_path

    def run_script(
        self,
        test_tmpdir: pathlib.Path,
        archive: pathlib.Path,
        vendor_archive: pathlib.Path,
        vendor_digest: pathlib.Path,
        output_root: pathlib.Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({"BAZEL_TEST": "1", "TEST_TMPDIR": str(test_tmpdir)})
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--archive",
                str(archive),
                "--vendor-archive",
                str(vendor_archive),
                "--vendor-digest",
                str(vendor_digest),
                "--output-root",
                str(output_root),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_extracts_regular_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            archive = self.make_archive(root)
            vendor_archive, vendor_digest = self.make_vendor_archive(root)
            output_root = root / "output"

            result = self.run_script(root, archive, vendor_archive, vendor_digest, output_root)

            self.assertEqual(result.returncode, 0, result.stderr)
            source_root = pathlib.Path(result.stdout.strip())
            self.assertEqual(source_root, output_root / ROOT)
            self.assertTrue((source_root / "vendor" / "modules.txt").is_file())

    def test_rejects_links_and_traversal_before_writing(self) -> None:
        cases: list[tuple[str, tarfile.TarInfo, bytes | None, str]] = []
        symlink = tarfile.TarInfo(f"{ROOT}/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../outside"
        cases.append(("symlink", symlink, None, "must not contain links"))
        traversal = tarfile.TarInfo(f"{ROOT}/../escape")
        traversal.size = len(b"escape\n")
        cases.append(("traversal", traversal, b"escape\n", "unsafe path"))

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            for case_name, member, contents, expected_error in cases:
                with self.subTest(case=case_name):
                    case_root = root / case_name
                    case_root.mkdir()
                    archive = self.make_archive(case_root, [(member, contents)])
                    vendor_archive, vendor_digest = self.make_vendor_archive(case_root)
                    output_root = case_root / "output"

                    result = self.run_script(
                        case_root, archive, vendor_archive, vendor_digest, output_root
                    )

                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stderr)
                    self.assertFalse(output_root.exists())

    def test_rejects_output_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            test_tmpdir = root / "test-tmpdir"
            test_tmpdir.mkdir()
            archive = self.make_archive(root)
            vendor_archive, vendor_digest = self.make_vendor_archive(root)
            output_root = test_tmpdir / ".." / "outside"

            result = self.run_script(
                test_tmpdir, archive, vendor_archive, vendor_digest, output_root
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TEST_TMPDIR", result.stderr)

    def test_rejects_source_archive_vendor_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            member = tarfile.TarInfo(f"{ROOT}/vendor/modules.txt")
            member.size = len(b"unreviewed vendor\n")
            archive = self.make_archive(root, [(member, b"unreviewed vendor\n")])
            vendor_archive, vendor_digest = self.make_vendor_archive(root)
            output_root = root / "output"

            result = self.run_script(root, archive, vendor_archive, vendor_digest, output_root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not contain a vendor tree", result.stderr)
            self.assertFalse(output_root.exists())

    def test_rejects_vendor_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = pathlib.Path(temporary_directory)
            archive = self.make_archive(root)
            vendor_archive, vendor_digest = self.make_vendor_archive(root)
            vendor_digest.write_text("0" * 64 + "\n", encoding="utf-8")

            result = self.run_script(root, archive, vendor_archive, vendor_digest, root / "output")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cloudflared vendor tree digest mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
