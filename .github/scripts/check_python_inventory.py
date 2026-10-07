# SPDX-License-Identifier: Apache-2.0
"""Check flat-source package coverage and interpreter-specific shadowing hazards."""
import argparse
import importlib.machinery
import sys
import sysconfig
import zipfile
from pathlib import Path

# These are installation/test artifacts, never runtime package sources.
EXCLUDED = {"tests", "build", "dist", "venv", ".venv", "__pycache__", ".git"}


def excluded(path):
    return any(part in EXCLUDED or part.endswith(".egg-info") for part in path.parts)


def stdlib_names():
    if hasattr(sys, "stdlib_module_names"):
        return set(sys.stdlib_module_names)
    # Python 3.9 has no stdlib_module_names. Inspect only this interpreter's
    # stdlib and extension directories, never site-packages or user imports.
    names = set(sys.builtin_module_names)
    directories = {sysconfig.get_path("stdlib"), sysconfig.get_path("platstdlib"),
                   sysconfig.get_config_var("DESTSHARED"),
                   str(Path(sysconfig.get_path("stdlib")) / "lib-dynload")}
    for directory in filter(None, directories):
        if not Path(directory).is_dir():
            continue
        for path in Path(directory).iterdir():
            if path.suffix == ".py":
                names.add(path.stem)
            elif path.is_dir() and (path / "__init__.py").is_file():
                names.add(path.name)
            else:
                for suffix in importlib.machinery.EXTENSION_SUFFIXES:
                    if path.name.endswith(suffix):
                        names.add(path.name[:-len(suffix)])
    return names


def validate(root, wheel=None):
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # build's TOML dependency on Python <3.11
    config = tomllib.loads((root / "pyproject.toml").read_text())
    configured = set(config["tool"]["setuptools"]["packages"])
    sources = {p.relative_to(root) for p in root.rglob("*.py")
               if not excluded(p.relative_to(root))}
    packages = {"cll" + ("." + ".".join(p.parent.parts) if p.parent.parts else "")
                for p in sources if p.name == "__init__.py"}
    if packages != configured:
        raise ValueError(f"source/configured package mismatch: missing={sorted(packages - configured)}, stale={sorted(configured - packages)}")
    top_level = {p.stem for p in sources if len(p.parts) == 1 and p.name != "__init__.py"}
    top_level.update(p.parts[0] for p in sources if len(p.parts) == 2 and p.name == "__init__.py")
    collisions = top_level & stdlib_names()
    if collisions:
        raise ValueError(f"top-level sources shadow stdlib: {sorted(collisions)}")
    if wheel:
        with zipfile.ZipFile(wheel) as archive:
            installed = {Path(name).relative_to("cll") for name in archive.namelist()
                         if name.startswith("cll/") and name.endswith(".py")}
        if sources != installed:
            raise ValueError(f"source/wheel module mismatch: missing={sorted(map(str, sources - installed))}, unexpected={sorted(map(str, installed - sources))}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--wheel", type=Path)
    args = parser.parse_args()
    validate(args.root, args.wheel)
