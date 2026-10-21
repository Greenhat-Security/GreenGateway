"""Tests for the pin and build-script checks behind the issue #426 upgrade pair."""
import json
from pathlib import Path
import tempfile
import unittest

import build_upgrade_pair as pair

PREPARED = "0" * 39 + "1"
SUCCESSOR = "0" * 39 + "2"


class PinTests(unittest.TestCase):
    def write(self, value) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        with handle:
            json.dump(value, handle)
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def pin(self, prepared=PREPARED, successor=SUCCESSOR, schema=1):
        return {"schema": schema, "prepared": {"commit": prepared}, "successor": {"commit": successor}}

    def test_the_repositorys_pin_names_two_distinct_full_commits(self):
        pin = pair.load_pin(pair.PIN)
        self.assertNotEqual(pin["prepared"]["commit"], pin["successor"]["commit"])
        self.assertEqual(pin["issue"], 426)

    def test_a_valid_pin_loads(self):
        pin = pair.load_pin(self.write(self.pin()))
        self.assertEqual(pin["successor"]["commit"], SUCCESSOR)

    def test_one_commit_twice_is_not_a_pair(self):
        with self.assertRaisesRegex(pair.PairError, "must differ"):
            pair.load_pin(self.write(self.pin(successor=PREPARED)))

    def test_only_full_lowercase_shas_are_accepted(self):
        for commit in ("303908b", PREPARED.upper().replace("0", "A"), "g" * 40, PREPARED + "0", "", None, 7):
            with self.subTest(commit=commit):
                with self.assertRaisesRegex(pair.PairError, "full lowercase commit SHA"):
                    pair.load_pin(self.write(self.pin(prepared=commit)))

    def test_an_unknown_schema_or_shape_is_refused(self):
        for value in (self.pin(schema=2), [], {"schema": 1}, {"schema": 1, "prepared": PREPARED}):
            with self.subTest(value=value):
                with self.assertRaises(pair.PairError):
                    pair.load_pin(self.write(value))

    def test_an_unreadable_pin_is_refused(self):
        with self.assertRaisesRegex(pair.PairError, "cannot read"):
            pair.load_pin(Path(tempfile.gettempdir()) / "no-such-upgrade-pair-pin.json")


class BuildScriptTests(unittest.TestCase):
    def test_the_repositorys_build_script_emits_no_rust_configuration(self):
        pair.check_build_script((pair.ROOT / "gateway" / "build.rs").read_text(encoding="utf-8"))
        pair.check_manifest((pair.ROOT / "gateway" / "Cargo.toml").read_text(encoding="utf-8"))

    def test_a_build_script_that_configures_rustc_cannot_be_replaced(self):
        for line in ('println!("cargo:rustc-cfg=feature_x");',
                     'println!("cargo::rustc-env=BUILD=1");',
                     'println!("cargo:rustc-link-lib=ssl");'):
            with self.subTest(line=line):
                with self.assertRaisesRegex(pair.PairError, "emits Rust configuration"):
                    pair.check_build_script("fn main() {\n    " + line + "\n}\n")
        pair.check_build_script('fn main() { println!("cargo:rerun-if-changed=src"); }')

    def test_a_manifest_naming_its_own_build_script_is_refused(self):
        with self.assertRaisesRegex(pair.PairError, "names its own build script"):
            pair.check_manifest('[package]\nname = "gateway"\nbuild = "generate.rs"\n')


if __name__ == "__main__":
    unittest.main()
