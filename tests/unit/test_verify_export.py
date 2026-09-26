import hashlib
import json
import tempfile
import unittest
from pathlib import Path
import importlib.util

SOURCE = Path(__file__).resolve().parents[2] / "scripts" / "verify-export.py"
SPEC = importlib.util.spec_from_file_location("verify_export", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifyExportTests(unittest.TestCase):
    def test_hash_row_count_and_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "events-2026-09.ndjson"
            artifact.write_bytes(b'{"id":"a"}\n')
            data = artifact.read_bytes()
            manifest = {
                "schemaVersion": 1,
                "artifacts": [{"name": artifact.name, "byteSize": len(data),
                               "sha256": hashlib.sha256(data).hexdigest(),
                               "rowCount": 1}],
            }
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(1, MODULE.verify_bundle(path, root, expected))
            artifact.write_bytes(b'{"id":"changed"}\n')
            with self.assertRaises(ValueError):
                MODULE.verify_bundle(path, root, expected)
            manifest["artifacts"][0]["name"] = "../outside"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.verify_bundle(path, root)


if __name__ == "__main__":
    unittest.main()
