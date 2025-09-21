#!/usr/bin/env bash
set -euo pipefail

# DriveBy Android APK build script for WSL (Ubuntu)
# This script:
# 1) Installs build prerequisites (OpenJDK, Python tools, etc.)
# 2) Installs Buildozer (which manages the Android SDK/NDK via python-for-android)
# 3) Builds a debug APK using the staged Kivy app under android_app/build
#
# Usage from Windows PowerShell/CMD:
#   wsl -e bash -lc "bash /mnt/c/Users/psybo/Desktop/Projects/free-wifi/scripts/wsl_build_apk.sh"
#
# APK output will be placed under:
#   /mnt/c/Users/psybo/Desktop/Projects/free-wifi/android_app/build/bin/
# And also copied to:
#   /mnt/c/Users/psybo/Desktop/Projects/free-wifi/DriveBy-debug.apk

# Adjust this only if your Windows user or path is different
WIN_PROJECT_PATH="/mnt/c/Users/psybo/Desktop/Projects/free-wifi"
ANDROID_DIR="$WIN_PROJECT_PATH/android_app"

echo "Updating apt and installing system prerequisites..."
sudo apt-get update -y
sudo apt-get install -y \
  build-essential \
  openjdk-17-jdk \
  python3 \
  python3-pip \
  python3-venv \
  git \
  unzip \
  zip \
  libffi-dev \
  libssl-dev \
  liblzma-dev \
  zlib1g-dev \
  libncurses-dev \
  libsqlite3-dev \
  pkg-config \
  ccache

# Ensure pip user bin is on PATH (legacy) and prepare a dedicated virtualenv to avoid PEP 668 issues
export PATH="$HOME/.local/bin:$PATH"

# Create and use an isolated virtual environment for Buildozer & tooling
VENV_DIR="$HOME/.venvs/driveby-buildozer"
VENV_BIN="$VENV_DIR/bin"
mkdir -p "$(dirname "$VENV_DIR")"
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment at $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "$VENV_BIN/activate"

echo "Upgrading pip/setuptools/wheel inside venv..."
pip install --upgrade pip setuptools wheel

echo "Installing Buildozer and Cython into venv..."
pip install Cython buildozer

# Optional: Kivy installed via recipes; not required here:
# python3 -m pip install --user kivy kivymd plyer

echo "Entering Android project directory: $ANDROID_DIR"
cd "$ANDROID_DIR"

# Initialize Buildozer project if needed (safe if already exists)
if [ ! -d ".buildozer" ]; then
  echo "Initializing Buildozer..."
  buildozer init || true
fi

echo "Starting APK build (debug)..."
# This will download Android SDK/NDK/Tools on first run; may take a long time
buildozer android debug

# Copy resulting APK to project root for convenience
APK_OUT="$ANDROID_DIR/bin"
FINAL_OUT="$WIN_PROJECT_PATH/DriveBy-debug.apk"

if compgen -G "$APK_OUT/*.apk" > /dev/null; then
  APK_PATH="$(ls -1t "$APK_OUT"/*.apk | head -n 1)"
  echo "Built APK: $APK_PATH"
  cp -f "$APK_PATH" "$FINAL_OUT"
  echo "Copied APK to: $FINAL_OUT"
else
  echo "ERROR: No APK found in $APK_OUT"
  exit 1
fi

echo "Done. APK is available at:"
echo " - $APK_OUT"
echo " - $FINAL_OUT"
