#!/usr/bin/env python3
"""
Windows Monitor Launcher (Python)
Bridges Windows persistence wrappers that expect a Python script by invoking the existing PowerShell monitor.
"""

import subprocess
import sys
import time
from pathlib import Path


def main():
    ps1_path = Path(__file__).with_name("windows_monitor.ps1")

    if not ps1_path.exists():
        print(f"[windows_monitor] Missing PowerShell script: {ps1_path}")
        sys.exit(0)

    while True:
        try:
            # Run the PowerShell monitor script with minimal footprint
            subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ps1_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

            # If the PS1 exits, wait a bit before relaunch
            time.sleep(30)

        except KeyboardInterrupt:
            break
        except Exception:
            # Back off on unexpected errors
            time.sleep(60)


if __name__ == "__main__":
    main()
