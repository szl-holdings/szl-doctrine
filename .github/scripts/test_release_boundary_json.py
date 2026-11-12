import importlib.util
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("release_boundary", HERE / "release_boundary.py")
RB = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(RB)


class StrictManifestJsonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_targets = RB.TARGET_IDS.copy()
        self.original_validate = RB._validate_entry
        RB.TARGET_IDS.clear()
        RB.TARGET_IDS["szl-holdings/example"] = 123

        def accept_entry(_repository: str, _value: object) -> None:
            return None

        RB._validate_entry = accept_entry

    def tearDown(self) -> None:
        RB.TARGET_IDS.clear()
        RB.TARGET_IDS.update(self.original_targets)
        RB._validate_entry = self.original_validate

    def _manifest_text(self, suffix: str) -> str:
        prefix = (
            '{"schema":"szl.release-boundary-manifest/v1",'
            '"source_repository":"szl-holdings/szl-doctrine",'
            '"targets":{"szl-holdings/example":{"repository_id":123'
        )
        return f"{prefix}{suffix}}}}}"

    def test_load_manifest_rejects_duplicate_top_level_members(self) -> None:
        path = self._write(
            '{"schema":"szl.release-boundary-manifest/v1",'
            '"schema":"szl.release-boundary-manifest/v1",'
            '"source_repository":"szl-holdings/szl-doctrine",'
            '"targets":{"szl-holdings/example":{}}}'
        )
        with self.assertRaises(ValueError):
            RB.load_manifest(path)

    def test_load_manifest_rejects_nonfinite_nested_number(self) -> None:
        path = self._write(self._manifest_text(',"value":1e999,"extra":{}}'))
        with self.assertRaises(ValueError):
            RB.load_manifest(path)

    def test_strict_json_accepts_finite_decimal(self) -> None:
        self.assertEqual(
            RB._strict_json('{"value":1.5,"exp":1e2}'),
            {"value": 1.5, "exp": 100.0},
        )

    def _write(self, text: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "manifest.json"
        path.write_text(text, encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
