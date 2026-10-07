# SPDX-License-Identifier: Apache-2.0
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from check_python_inventory import stdlib_names, validate


class InventoryGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("__init__.py")
        self.configure(["cll"])

    def write(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")

    def configure(self, packages):
        (self.root / "pyproject.toml").write_text(
            "[tool.setuptools]\npackages = " + repr(packages) + "\n")

    def wheel(self, names):
        path = self.root / "package.whl"
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                archive.writestr("cll/" + name, "")
        return path

    def test_current_sources_and_artifacts(self):
        for name in ["tests/types.py", "tests/__init__.py", "build/email/__init__.py",
                     ".venv/lib/types.py", "dist/types.py", "venv/types.py"]:
            self.write(name)
        validate(self.root, self.wheel(["__init__.py"]))

    def test_new_nested_package_must_be_configured(self):
        self.write("witness/__init__.py")
        self.write("witness/nested/__init__.py")
        with self.assertRaisesRegex(ValueError, "source/configured"):
            validate(self.root)
        self.configure(["cll", "cll.witness", "cll.witness.nested"])
        validate(self.root)

    def test_wheel_must_include_configured_package_and_modules(self):
        self.write("witness/__init__.py")
        self.write("witness/proof.py")
        self.configure(["cll", "cll.witness"])
        for names in [["__init__.py"], ["__init__.py", "witness/__init__.py"]]:
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, "source/wheel"):
                validate(self.root, self.wheel(names))
        validate(self.root, self.wheel(["__init__.py", "witness/__init__.py", "witness/proof.py"]))

    def test_stdlib_module_and_package_collisions(self):
        self.write("types.py")
        with self.assertRaisesRegex(ValueError, "shadow stdlib"):
            validate(self.root)
        (self.root / "types.py").unlink()
        self.write("email/__init__.py")
        self.configure(["cll", "cll.email"])
        with self.assertRaisesRegex(ValueError, "shadow stdlib"):
            validate(self.root)

    def test_python39_stdlib_fallback(self):
        # Exercise the fallback even when the test interpreter is newer.
        with patch("check_python_inventory.sys", builtin_module_names=("sys",)):
            # Mock has arbitrary attributes; explicitly remove the modern one.
            import check_python_inventory
            del check_python_inventory.sys.stdlib_module_names
            names = stdlib_names()
        self.assertTrue({"sys", "types", "email", "math"} <= names)


if __name__ == "__main__":
    unittest.main()
