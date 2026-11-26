"""Check the native Cargo graph boundary with disposable fixture packages."""

from pathlib import Path
import subprocess
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check_kernel_dependencies.sh").resolve()
TARGETS = ("aarch64-unknown-none", "x86_64-unknown-none")
HOST_ONLY = "host-only"


def write_package(workspace, name, settings="", source=""):
    package = workspace / name
    (package / "src").mkdir(parents=True)
    (package / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2024"\n{settings}',
        encoding="utf-8",
    )
    (package / "src" / "lib.rs").write_text(source, encoding="utf-8")


class KernelDependencyTests(unittest.TestCase):
    def test_target_dependency_is_rejected_and_host_proc_macro_is_allowed(self):
        with tempfile.TemporaryDirectory(prefix="apfs-kernel-graph-") as directory:
            workspace = Path(directory)
            (workspace / "Cargo.toml").write_text(
                '[workspace]\nresolver = "3"\nmembers = ["apfs-core", "derive", "host-std"]\n',
                encoding="utf-8",
            )
            write_package(
                workspace,
                "apfs-core",
                f"""
[features]
{HOST_ONLY} = ["dep:host-std"]

[dependencies]
derive = {{ path = "../derive" }}
host-std = {{ path = "../host-std", optional = true }}
""",
                "#![no_std]\n",
            )
            write_package(
                workspace,
                "derive",
                """
[lib]
proc-macro = true

[dependencies]
host-std = { path = "../host-std" }
""",
            )
            write_package(
                workspace,
                "host-std",
                source="pub fn working_directory() -> std::io::Result<std::path::PathBuf> { std::env::current_dir() }\n",
            )
            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"], cwd=workspace, check=True
            )
            for target in TARGETS:
                with self.subTest(target=target):
                    command = ["bash", str(CHECKER), "apfs-core", target]
                    clean = subprocess.run(
                        command, cwd=workspace, capture_output=True, text=True
                    )
                    self.assertEqual(clean.returncode, 0, clean.stderr)
                    rejected = subprocess.run(
                        [*command, "--features", HOST_ONLY],
                        cwd=workspace,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(rejected.returncode, 1, rejected.stderr)
                    self.assertIn("unexpected kernel dependency graph", rejected.stderr)
                    self.assertIn("host-std", rejected.stderr.splitlines())


if __name__ == "__main__":
    unittest.main()
