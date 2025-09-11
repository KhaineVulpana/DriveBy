#!/usr/bin/env python3
"""
DriveBy APK Builder
Automated script to build DriveBy Android APK using Buildozer
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

class DriveByAPKBuilder:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.android_dir = Path(__file__).parent
        self.build_dir = self.android_dir / "build"

    def setup_build_environment(self):
        """Setup the build environment"""
        print(" Setting up build environment...")

        # Create build directory
        self.build_dir.mkdir(exist_ok=True)

        # Copy all necessary files to build directory
        files_to_copy = [
        # Core DriveBy files
        "phone_host.py",
        "data_server.py",
        "mobile_dashboard.py",
        "login_proxy.py",
        "start.py",
        "config.json",
        "privacy_protection.py",
        "privacy_protection_2024.py",
        "security_bypass.py",

        # Requirements
        "requirements.txt",
        "requirements_2024.txt",

        # Documentation
        "README.md",
        "setup.md"
        ]

        # Copy files
        for file_name in files_to_copy:
            src = self.project_root / file_name
            if src.exists():
                dst = self.build_dir / file_name
                shutil.copy2(src, dst)
                print(f" Copied {file_name}")

                # Copy directories
                dirs_to_copy = [
                "payloads",
                "security_bypass",
                "web"
                ]

                for dir_name in dirs_to_copy:
                    src = self.project_root / dir_name
                    if src.exists():
                        dst = self.build_dir / dir_name
                        if dst.exists():
                            shutil.rmtree(dst)
                            shutil.copytree(src, dst)
                            print(f" Copied {dir_name}/ directory")

                            # Copy Android app files
                            android_files = [
                            "main.py",
                            "buildozer.spec",
                            "android_manifest_template.xml"
                            ]

                            for file_name in android_files:
                                src = self.android_dir / file_name
                                dst = self.build_dir / file_name
                                shutil.copy2(src, dst)
                                print(f" Copied {file_name}")

def install_dependencies(self):
    """Install required dependencies for building"""
    print(" Installing build dependencies...")

    dependencies = [
    "buildozer",
    "cython",
    "kivy",
    "kivymd",
    "plyer"
    ]

    for dep in dependencies:
        try:
            result = subprocess.run([
            sys.executable, "-m", "pip", "install", dep
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print(f" Installed {dep}")
            else:
                print(f" Failed to install {dep}: {result.stderr}")
        except Exception as e:
                print(f" Error installing {dep}: {e}")

def build_apk(self, debug=True):
    """Build the APK using Buildozer"""
    print(" Building DriveBy APK...")

    # Change to build directory
    original_cwd = os.getcwd()
    os.chdir(self.build_dir)

    try:
        # Initialize buildozer if needed
        if not (self.build_dir / ".buildozer").exists():
            print(" Initializing Buildozer...")
            result = subprocess.run(["buildozer", "init"], capture_output=True, text=True)
            if result.returncode != 0:
                print(f" Buildozer init failed: {result.stderr}")
                return False

                # Build APK
                build_command = ["buildozer", "android", "debug" if debug else "release"]
                print(f" Running: {' '.join(build_command)}")

                # Run build process
                process = subprocess.Popen(
                build_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
                )

                # Stream output
                for line in process.stdout:
                    print(line.rstrip())

                    process.wait()

                    if process.returncode == 0:
                        print(" APK build completed successfully!")

                        # Find the built APK
                        bin_dir = self.build_dir / "bin"
                        if bin_dir.exists():
                            apk_files = list(bin_dir.glob("*.apk"))
                            if apk_files:
                                apk_path = apk_files[0]
                                print(f" APK created: {apk_path}")

                                # Copy APK to project root
                                final_apk = self.project_root / f"DriveBy-{'debug' if debug else 'release'}.apk"
                                shutil.copy2(apk_path, final_apk)
                                print(f" APK copied to: {final_apk}")

                                return True

                                print(" APK file not found in bin directory")
                                return False
                            else:
                                print(f" APK build failed with return code: {process.returncode}")
                                return False

    except Exception as e:
                                print(f" Build error: {e}")
                                return False
    finally:
                                os.chdir(original_cwd)

def create_signing_config(self):
    """Create signing configuration for release builds"""
    print(" Creating signing configuration...")

    keystore_path = self.build_dir / "driveby.keystore"

    if not keystore_path.exists():
        # Generate keystore
        keytool_cmd = [
        "keytool", "-genkey", "-v",
        "-keystore", str(keystore_path),
        "-alias", "driveby",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", "driveby123",
        "-keypass", "driveby123",
        "-dname", "CN=DriveBy,OU=Security,O=DriveBy,L=Unknown,S=Unknown,C=US"
        ]

        try:
            result = subprocess.run(keytool_cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(" Keystore created successfully")
                return True
            else:
                print(f" Keystore creation failed: {result.stderr}")
                return False
        except FileNotFoundError:
                print(" keytool not found. Please install Java JDK")
                return False
            else:
                print(" Keystore already exists")
                return True

def clean_build(self):
    """Clean build artifacts"""
    print("🧹 Cleaning build artifacts...")

    if self.build_dir.exists():
        shutil.rmtree(self.build_dir)
        print(" Build directory cleaned")

def build_full_apk(self, clean=False, debug=True):
    """Complete APK build process"""
    print(" Starting DriveBy APK build process...")
    print("=" * 50)

    if clean:
        self.clean_build()

        # Setup environment
        self.setup_build_environment()

        # Install dependencies
        self.install_dependencies()

        # Create signing config for release builds
        if not debug:
            if not self.create_signing_config():
                print(" Failed to create signing configuration")
                return False

                # Build APK
                success = self.build_apk(debug=debug)

                if success:
                    print("\n" + "=" * 50)
                    print(" DriveBy APK build completed successfully!")
                    print(" You can now install the APK on your Android device")
                    print(" Make sure to enable 'Install from unknown sources' in Android settings")
                    print("=" * 50)
                else:
                    print("\n" + "=" * 50)
                    print(" APK build failed")
                    print(" Check the build logs above for error details")
                    print("=" * 50)

                    return success

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Build DriveBy Android APK")
    parser.add_argument("--clean", action="store_true", help="Clean build artifacts first")
    parser.add_argument("--release", action="store_true", help="Build release APK (default: debug)")
    parser.add_argument("--setup-only", action="store_true", help="Only setup build environment")

    args = parser.parse_args()

    builder = DriveByAPKBuilder()

    if args.setup_only:
        builder.setup_build_environment()
        print(" Build environment setup complete")
        return

        debug = not args.release
        success = builder.build_full_apk(clean=args.clean, debug=debug)

        sys.exit(0 if success else 1)

        if __name__ == "__main__":
            main()
