import importlib.util, json, pathlib, tempfile, os, sys, unittest

spec = importlib.util.spec_from_file_location(
    "repair", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "repair_conflict_markers.py")
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)

CORRUPT = '{\n"a": 1,\n<<<<<<< Updated upstream\n"b": 1,\n=======\n"b": 2,\n>>>>>>> Stashed changes\n"c": 3\n}\n'


class RepairTests(unittest.TestCase):
    def test_detects_markers(self):
        self.assertTrue(repair.has_markers(CORRUPT))
        self.assertFalse(repair.has_markers('{"a": 1}'))

    def test_keeps_fresh_second_side_and_yields_valid_json(self):
        fixed = repair.resolve_second_side(CORRUPT)
        self.assertEqual(json.loads(fixed), {"a": 1, "b": 2, "c": 3})

    def test_clean_text_untouched(self):
        self.assertEqual(repair.resolve_second_side('x\ny\n'), 'x\ny\n')

    def test_valid_rejects_bad_json_and_markers(self):
        p = pathlib.Path("x.json")
        self.assertFalse(repair.valid(p, CORRUPT))
        self.assertTrue(repair.valid(p, '{"ok": true}'))


if __name__ == "__main__":
    unittest.main()
