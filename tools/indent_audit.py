import os
import py_compile
import json
from typing import List, Dict

"""
Indentation audit script:
- Walks the current project recursively
- Attempts to py_compile all .py files
- Reports only files with IndentationError or TabError (likely indentation issues)
- Outputs JSON lines for easy parsing
"""

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def collect_python_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip common non-source directories if needed (none for now)
        for fn in filenames:
            if fn.endswith(".py"):
                files.append(os.path.join(dirpath, fn))
    return files

def audit_files(files: List[str]) -> List[Dict]:
    issues: List[Dict] = []
    for path in files:
        try:
            py_compile.compile(path, doraise=True)
        except Exception as e:
            err_text = str(e)
            err_type = type(e).__name__
            # Normalize path to be relative and POSIX-style
            rel = os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")
            # Filter: keep only indentation-related errors
            if ("IndentationError" in err_text) or ("TabError" in err_text) or ("expected an indented block" in err_text):
                issues.append({
                    "file": rel,
                    "error_type": err_type,
                    "message": err_text
                })
    return issues

def main():
    files = collect_python_files(PROJECT_ROOT)
    issues = audit_files(files)
    if not issues:
        print("[]")
        return
    for issue in issues:
        print(json.dumps(issue, ensure_ascii=False))

if __name__ == "__main__":
    main()
