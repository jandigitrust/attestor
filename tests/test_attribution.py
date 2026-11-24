"""Packaging preserves notices from the resolved dependency graph."""

import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from collect_licenses import collect


class AttributionTests(unittest.TestCase):
    def test_project_crate_is_excluded_from_dependency_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "native"
            output = package / "licenses"
            dependency = root / "dependency"
            output.mkdir(parents=True)
            dependency.mkdir()
            (output / "third-party-licenses.tar.gz").write_bytes(b"old archive")
            (dependency / "LICENSE").write_text("dependency licence")
            metadata = {
                "workspace_members": ["project"],
                "resolve": {"nodes": [{"id": "project"}, {"id": "dependency"}]},
                "packages": [
                    {"id": "project", "manifest_path": str(package / "Cargo.toml")},
                    {
                        "id": "dependency",
                        "name": "dependency",
                        "version": "1.0.0",
                        "manifest_path": str(dependency / "Cargo.toml"),
                        "source": "registry+https://example.invalid/index",
                    },
                ],
            }
            collect(
                metadata,
                output / "third-party-licenses.tar.gz",
                project_crates={package},
            )
            with tarfile.open(output / "third-party-licenses.tar.gz") as archive:
                inventory = json.load(archive.extractfile("third-party/packages.json"))
                self.assertEqual([item["name"] for item in inventory], ["dependency"])
                self.assertFalse(
                    any(name.endswith(".tar.gz") for name in archive.getnames())
                )

    def test_git_workspace_notices_require_the_resolved_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / "core"
            crate.mkdir()
            (root / ".git").mkdir()
            (root / "LICENSE").write_text("workspace licence")
            revision = "a" * 40
            metadata = {
                "resolve": {"nodes": [{"id": "core"}]},
                "packages": [
                    {
                        "id": "core",
                        "name": "core",
                        "version": "0.2.0",
                        "manifest_path": str(crate / "Cargo.toml"),
                        "source": "git+https://example.invalid/evidence#" + revision,
                    }
                ],
            }
            output = root / "attribution.tar.gz"
            with patch(
                "collect_licenses.subprocess.check_output", return_value=revision
            ):
                collect(metadata, output)
            with tarfile.open(output) as archive:
                self.assertTrue(
                    any(
                        name.endswith("repository/LICENSE")
                        for name in archive.getnames()
                    )
                )
            with patch(
                "collect_licenses.subprocess.check_output", return_value="b" * 40
            ):
                with self.assertRaisesRegex(ValueError, "Git revision differs"):
                    collect(metadata, output)


if __name__ == "__main__":
    unittest.main()
