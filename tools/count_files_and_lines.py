import os
import sys


EXCLUDE_DIRS = {
    "__pycache__",
    ".venv",
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".eggs",
    ".idea",
    ".vscode",
    ".parcel-cache",
    "coverage",
}


def count_files_and_lines(root: str) -> tuple[int, int]:
    total_files = 0
    total_lines = 0

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip common virtualenv, cache, VCS, and build directories
        dirnames[:] = [
            d for d in dirnames
            if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")
        ]

        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                # Count file
                total_files += 1

                # Count newlines efficiently in binary mode
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        total_lines += chunk.count(b"\n")
            except Exception:
                # Ignore unreadable files
                continue

    return total_files, total_lines


def main() -> int:
    root = os.getcwd()
    files, lines = count_files_and_lines(root)
    # Print in a stable, parseable format
    print(f"FILES={files}")
    print(f"LINES={lines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
