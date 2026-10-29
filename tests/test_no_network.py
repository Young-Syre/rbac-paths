"""The package must have no way to reach the network, and no dependencies.

This is enforced structurally rather than by trust: every module in the
package is parsed and every import it declares is checked against a deny list,
and the whole import graph is checked for third-party modules.
"""

from __future__ import annotations

import ast
import os
import sys
import unittest

import rbac_paths

PACKAGE_DIR = os.path.dirname(os.path.abspath(rbac_paths.__file__))

#: Anything that can open a socket, spawn a process, or load code at runtime.
FORBIDDEN = frozenset(
    {
        "asyncio",
        "ctypes",
        "ftplib",
        "http",
        "httplib",
        "httpx",
        "imaplib",
        "kubernetes",
        "multiprocessing",
        "poplib",
        "requests",
        "selectors",
        "smtplib",
        "socket",
        "socketserver",
        "ssl",
        "subprocess",
        "telnetlib",
        "urllib",
        "urllib2",
        "urllib3",
        "webbrowser",
        "xmlrpc",
        "yaml",
    }
)

#: Standard library modules the package is allowed to import.  Keeping this an
#: allow list rather than only a deny list means a new dependency cannot slip
#: in unnoticed.
ALLOWED = frozenset(
    {
        "__future__",
        "argparse",
        "ast",
        "collections",
        "collections.abc",
        "dataclasses",
        "enum",
        "json",
        "os",
        "re",
        "sys",
        "textwrap",
        "typing",
    }
)


def package_files() -> list[str]:
    return sorted(
        os.path.join(PACKAGE_DIR, name)
        for name in os.listdir(PACKAGE_DIR)
        if name.endswith(".py")
    )


def imports_in(path: str) -> set[str]:
    """Every module name imported by one file, relative imports excluded."""
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # A relative import, i.e. inside this package.
                continue
            if node.module:
                found.add(node.module)
    return found


class SourceTests(unittest.TestCase):
    def test_the_package_has_modules_to_check(self):
        self.assertGreaterEqual(len(package_files()), 8)

    def test_no_module_imports_anything_that_can_reach_the_network(self):
        for path in package_files():
            for name in imports_in(path):
                root = name.split(".")[0]
                self.assertNotIn(
                    root, FORBIDDEN, f"{os.path.basename(path)} imports {name}"
                )

    def test_every_import_is_on_the_allow_list(self):
        for path in package_files():
            for name in imports_in(path):
                self.assertIn(
                    name,
                    ALLOWED,
                    f"{os.path.basename(path)} imports {name}, which is not allowed",
                )

    def test_no_module_calls_eval_exec_or_import_dunder(self):
        for path in package_files():
            with open(path, encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(
                        node.func.id,
                        ("eval", "exec", "compile", "__import__"),
                        os.path.basename(path),
                    )

    def test_no_source_file_mentions_a_url_scheme_outside_a_docs_reference(self):
        # References to kubernetes.io are documentation, not requests. Nothing
        # should name any other remote host.
        for path in package_files():
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            for scheme in ("http://",):
                self.assertNotIn(scheme, text, os.path.basename(path))
            for line in text.splitlines():
                if "https://" in line:
                    self.assertIn("kubernetes.io", line, f"{path}: {line.strip()}")


class ImportGraphTests(unittest.TestCase):
    def test_importing_the_package_loads_no_networking_module(self):
        # Import every module, then check what ended up in sys.modules. A
        # networking module already imported by the test runner would make this
        # a weak check, so only modules this package could have pulled in are
        # considered: the check is on the declared imports above, and this is
        # the belt to that braces.
        before = set(sys.modules)
        import rbac_paths.cli
        import rbac_paths.graph
        import rbac_paths.loader
        import rbac_paths.query
        import rbac_paths.render
        import rbac_paths.resolver
        import rbac_paths.rules  # noqa: F401

        newly_loaded = {name.split(".")[0] for name in set(sys.modules) - before}
        self.assertEqual(newly_loaded & FORBIDDEN, set())

    def test_the_package_declares_no_dependencies(self):
        # src/rbac_paths -> src -> the repository root.
        path = os.path.join(
            os.path.dirname(os.path.dirname(PACKAGE_DIR)), "pyproject.toml"
        )
        if not os.path.exists(path):  # pragma: no cover - installed wheel
            self.skipTest("pyproject.toml is not present in an installed copy")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("dependencies = []", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
