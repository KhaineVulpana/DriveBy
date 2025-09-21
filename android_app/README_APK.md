# DriveBy Android APK - Build & Installation Guide

This guide explains how to build and install the DriveBy home network cluster management system as an Android APK.

## Building the APK

### Prerequisites

1. **Python 3.8+** with pip installed
2. **Java JDK 8+** (for signing release APKs)
3. **Android SDK** (automatically downloaded by Buildozer)
4. **Git** (for downloading dependencies)
5. **Linux/macOS/WSL** (recommended for building)

### Quick Build

```bash
# Navigate to android_app directory
cd android_app

# Build debug APK (easiest option)
python build_apk.py

# Build release APK (for production)
python build_apk.py --release

# Clean build (removes all build artifacts first)
python build_apk.py --clean
```

### Manual Build Process

If you prefer to build manually:

```bash
# Install Buildozer
pip install buildozer cython kivy kivymd plyer

# Setup build environment
python build_apk.py --setup-only

# Navigate to build directory
cd build

# Initialize Buildozer (first time only)
buildozer init

# Build debug APK
buildozer android debug

# Build release APK
buildozer android release
```

## APK Features

The DriveBy Android APK includes:

### Core Functionality
- **Network Cluster Management**: Manage devices connecting to your phone's hotspot
- **Real-time Monitoring**: Live dashboard showing connected devices and status
- **Security Bypasses**: 50+ advanced security bypass methods for all major OS platforms
- **Privacy Protection**: Quantum-resistant encryption and advanced privacy techniques
- **Auto-deployment**: Automatically deploy payloads to connecting devices

### Security Features
- **Windows Bypasses**: EDR unhooking, AMSI bypass, Windows Defender evasion
- **Android Bypasses**: Root hiding, SafetyNet bypass, Play Protect evasion
- **macOS Bypasses**: Gatekeeper bypass, TCC bypass, XProtect evasion
- **Linux Bypasses**: SELinux bypass, container escape, namespace evasion
- **Cross-platform**: VM detection evasion, AI/ML evasion, steganography

### Mobile Interface
- **Material Design**: Modern Android UI with dark theme
- **Real-time Updates**: Live status updates every 5 seconds
- **Touch-friendly**: Optimized for mobile interaction
- **Background Service**: Runs in background even when app is closed

## Installation

### Installing the APK

1. **Enable Unknown Sources**:
 - Go to Android Settings → Security
 - Enable "Install from unknown sources" or "Allow from this source"

2. **Install APK**:
 ```bash
 # Transfer APK to your Android device
 adb install DriveBy-debug.apk

 # Or copy to device and install manually
 ```

3. **Grant Permissions**:
 - The app will request various permissions for full functionality
 - Grant all permissions for complete feature access

### First Run Setup

1. **Launch DriveBy** from your app drawer
2. **Grant Permissions** when prompted
3. **Start Service** by tapping "Start DriveBy"
4. **Enable Hotspot** on your Android device
5. **Connect Devices** to your hotspot to begin monitoring

## Configuration

### App Configuration

The APK uses the same `config.json` as the desktop version:

```json
{
 "server": {
 "host": "0.0.0.0",
 "port": 8080,
 "data_port": 8081
 },
 "network": {
 "interface": "wlan0",
 "scan_interval": 5,
 "hotspot_range": "192.168.43.0/24"
 }
}
```

### Android-Specific Settings

Additional Android settings in `buildozer.spec`:

```ini
# Permissions
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,CHANGE_WIFI_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,CAMERA,RECORD_AUDIO,ACCESS_FINE_LOCATION,SYSTEM_ALERT_WINDOW,WAKE_LOCK,FOREGROUND_SERVICE

# Target Android API
android.api = 33
android.minapi = 21

# Architecture support
android.archs = arm64-v8a, armeabi-v7a
```

## Usage

### Basic Operation

1. **Start the App**: Launch DriveBy from your Android device
2. **Start Service**: Tap "Start DriveBy" to begin monitoring
3. **Enable Hotspot**: Turn on your phone's WiFi hotspot
4. **Monitor Devices**: Watch the dashboard for connecting devices
5. **Deploy Payloads**: Payloads are automatically deployed to new devices

### Advanced Features

#### Security Bypasses
- Tap "Run Security Bypasses" to execute all available bypass methods
- View results in the system log
- Check security status in the status cards

#### Network Management
- Monitor connected devices in real-time
- View network status and configuration
- Access detailed logs and statistics

#### Background Operation
- The service runs in the background
- Continues monitoring even when app is minimized
- Survives device reboots (with proper permissions)

##  Troubleshooting

### Build Issues

**Buildozer fails to download SDK**:
```bash
# Set environment variables
export ANDROID_HOME=$HOME/.buildozer/android/platform/android-sdk
export PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools
```

**Python dependencies fail**:
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y git zip unzip openjdk-8-jdk python3-pip autoconf libtool pkg-config zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo5 cmake libffi-dev libssl-dev

# Install Python dependencies
pip install --upgrade pip setuptools wheel
pip install buildozer cython kivy kivymd
```

**Build fails with memory error**:
```bash
# Increase build memory
export GRADLE_OPTS="-Xmx4096m -Dorg.gradle.jvmargs=-Xmx4096m"
```

### Runtime Issues

**App crashes on startup**:
- Check Android version compatibility (minimum API 21)
- Ensure all permissions are granted
- Check device logs: `adb logcat | grep DriveBy`

**Network features not working**:
- Grant location and WiFi permissions
- Enable hotspot manually
- Check firewall/security software

**Security bypasses fail**:
- Some bypasses require root access
- Install on rooted device for full functionality
- Check individual bypass logs for specific errors

### Performance Optimization

**Reduce APK size**:
```ini
# In buildozer.spec
android.add_compile_options = "sourceCompatibility = 1.8", "targetCompatibility = 1.8"
android.gradle_dependencies =
```

**Improve startup time**:
- Use release build instead of debug
- Enable ProGuard optimization
- Reduce included Python modules

## Security Considerations

### Permissions

The APK requests extensive permissions for full functionality:

- **Network**: Monitor and control network connections
- **Storage**: Store payloads and collected data
- **Location**: Required for WiFi management on newer Android versions
- **Camera/Microphone**: For advanced monitoring capabilities
- **System**: Background operation and boot startup

### Privacy

- All data is processed locally on your device
- No data is sent to external servers
- Quantum-resistant encryption protects sensitive information
- Advanced privacy protection techniques are built-in

### Legal Notice

This tool is designed for legitimate home network management and security research. Users are responsible for ensuring compliance with local laws and regulations. Only use on networks and devices you own or have explicit permission to test.

## Additional Resources

- **Main Documentation**: See `../README.md` for complete system documentation
- **Security Bypasses**: See `../SECURITY_BYPASS.md` for detailed bypass information
- **Privacy Protection**: See `../PRIVACY_PROTECTION.md` for privacy features
- **Setup Guide**: See `../setup.md` for detailed setup instructions

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the main project documentation
3. Check Android device compatibility
4. Verify all permissions are granted
5. Test on a rooted device for full functionality

The DriveBy Android APK provides a complete mobile solution for home network cluster management with advanced security and privacy features.
