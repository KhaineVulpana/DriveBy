#!/usr/bin/env python3
"""
Compile audit:
- Recursively finds all .py files under project root.
- Attempts to py_compile each file.
- Prints JSON lines for any file that fails to compile.
- Exits with code 0 if all compiled, 1 if any failures.
"""
import os
import sys
import json
import py_compile
from typing import List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def collect_python_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip __pycache__
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(os.path.join(dirpath, fn))
    return files

def main() -> int:
    files = collect_python_files(PROJECT_ROOT)
    failures = 0
    for path in files:
        try:
            py_compile.compile(path, doraise=True)
        except Exception as e:
            rel = os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")
            print(json.dumps({
                "file": rel,
                "error_type": type(e).__name__,
                "message": str(e)
            }, ensure_ascii=False))
            failures += 1
    return 0 if failures == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
