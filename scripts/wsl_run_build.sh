#!/usr/bin/env bash
set -euo pipefail

# WSL helper: copy project into WSL filesystem and run Buildozer there.
# - Avoids operating on files located on the Windows filesystem during build.
# - Writes logs to android_app/build_logs inside the WSL copy and copies any produced APK back to the Windows project.
#
# Usage (from Windows): wsl.exe bash /mnt/c/Users/psybo/Desktop/Projects/free-wifi/scripts/wsl_run_build.sh
# Or from WSL: bash scripts/wsl_run_build.sh

TMP=/home/psybo/driveby_build
WIN_SRC="/mnt/c/Users/psybo/Desktop/Projects/free-wifi"
WSL_ANDROID_APP="$TMP/android_app"
WSL_BUILD_LOG_DIR="$WSL_ANDROID_APP/build_logs"

echo "[wsl_run_build] Preparing WSL build copy at: $TMP"
rm -rf "$TMP"
mkdir -p "$TMP"

echo "[wsl_run_build] Copying project into WSL filesystem (excludes .git, __pycache__, *.pyc)"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' "$WIN_SRC/" "$TMP/"
else
  cp -a "$WIN_SRC/." "$TMP/"
fi

# Activate buildozer venv if present
if [ -f "$HOME/.venvs/buildozer/bin/activate" ]; then
  echo "[wsl_run_build] Activating buildozer venv"
  # shellcheck source=/dev/null
  source "$HOME/.venvs/buildozer/bin/activate"
fi

cd "$WSL_ANDROID_APP"
mkdir -p "$WSL_BUILD_LOG_DIR"
LOG="$WSL_BUILD_LOG_DIR/apk_build_$(date +%Y%m%d_%H%M%S).log"
echo "[wsl_run_build] Running buildozer android debug (logs -> $LOG)"

# Prefer buildozer from venv, then PATH
if [ -x "$HOME/.venvs/buildozer/bin/buildozer" ]; then
  BUILDOZER_CMD="$HOME/.venvs/buildozer/bin/buildozer"
elif command -v buildozer >/dev/null 2>&1; then
  BUILDOZER_CMD="$(command -v buildozer)"
else
  echo "[wsl_run_build] ERROR: buildozer not found in venv or PATH. Install buildozer in WSL first."
  exit 2
fi

# Run build and capture exit code
if ! "$BUILDOZER_CMD" android debug > "$LOG" 2>&1; then
  echo "BUILD_FAILED"
  echo "Log: $LOG"
  # copy log back to Windows project for inspection
  cp -f "$LOG" /mnt/c/Users/psybo/Desktop/Projects/free-wifi/android_app/build_logs/ || true
  exit 1
fi

echo "BUILD_OK"
echo "Log: $LOG"

# Copy log and any APK back to Windows project
cp -f "$LOG" /mnt/c/Users/psybo/Desktop/Projects/free-wifi/android_app/build_logs/ || true

# Try to find the built APK(s) and copy the first one back to Windows android_app/bin
APK_PATH=$(find . -type f -name "*.apk" | head -n1 || true)
if [ -n "$APK_PATH" ]; then
  echo "[wsl_run_build] APK found: $APK_PATH"
  mkdir -p /mnt/c/Users/psybo/Desktop/Projects/free-wifi/android_app/bin/
  cp -f "$APK_PATH" /mnt/c/Users/psybo/Desktop/Projects/free-wifi/android_app/bin/ || true
  echo "[wsl_run_build] Copied APK to Windows project android_app/bin/"
else
  echo "[wsl_run_build] No APK found in WSL android_app directory"
fi

echo "[wsl_run_build] Done."
