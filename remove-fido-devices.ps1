# Script to remove all entries in 'Linked Devices' folders under FIDO registry path
# Requires running with administrative privileges

$ErrorActionPreference = 'Stop'

function Remove-FIDOLinkedDevices {
    try {
        # Define the base registry path
        $basePath = "Registry::HKEY_USERS\S-1-5-20\Software\Microsoft\Cryptography\FIDO"
        
        # Verify the base path exists
        if (-not (Test-Path -Path $basePath)) {
            Write-Error "Base registry path not found: $basePath"
            return
        }

        # Get all subfolders under the FIDO path
        $fidoSubfolders = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue

        if (-not $fidoSubfolders) {
            Write-Host "No FIDO subfolders found."
            return
        }

        foreach ($folder in $fidoSubfolders) {
            $linkedDevicesPath = Join-Path $folder.PSPath "LinkedDevices"
            
            # Check if Linked Devices folder exists
            if (Test-Path -Path $linkedDevicesPath) {
                Write-Host "Processing: $linkedDevicesPath"
                
                # Get all entries in the Linked Devices folder
                $devices = Get-ChildItem -Path $linkedDevicesPath -ErrorAction SilentlyContinue
		
		echo $folder
		echo $devices                

                if ($devices) {
                    foreach ($device in $devices) {
                        try {
                            Remove-Item -Path $device.PSPath -Force -Recurse
                            Write-Host "Removed device: $($device.PSPath)" -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "Failed to remove device: $($device.PSPath). Error: $_"
                        }
                    }
                }
                else {
                    Write-Host "No devices found in: $linkedDevicesPath"
                }
            }
            else {
                Write-Host "No 'Linked Devices' folder found in: $($folder.PSPath)"
            }
        }
        
        Write-Host "Operation completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

# Check if running with administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script requires administrative privileges. Please run PowerShell as Administrator."
    exit 1
}

# Execute the function
Remove-FIDOLinkedDevices
