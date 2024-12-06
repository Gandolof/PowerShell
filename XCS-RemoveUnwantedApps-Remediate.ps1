<#
.SYNOPSIS
    Remediates specified unwanted applications by uninstalling them from the system.

.DESCRIPTION
    This script checks for the presence of specified unwanted applications, including AppX provisioned packages, AppX packages, and Win32 applications.
    If any of the specified applications are found, the script attempts to uninstall them.

.PARAMETER
    None.

.EXAMPLE
    .\XCS-RemoveUnwantedApps-Remediate.ps1

.NOTES
    Author: Björn Hedenström
    Company: Xperta AB
    Date: 2023-12-06
    Version: 0.9

.NOTES
    2023-10-10: Initial version.
    2023-11-25: Updated to include additional app names.
    2023-12-01: Updated to include detection of Win32 apps.
    2023-12-02: Updated to return a status code indicating whether any apps were found.
    2023-12-03: Updated to include a timeout for uninstall operations. Removed it again. Todo: Use Start-Job/Wait-Job.
    2023-12-04: Updated to handle most (if not all) uninstall scenarios for Win32 apps.
    2023-12-06: Updated to use winget as the primary uninstall method.
    2023-12-06: Updated to Uninstall AppX Packages too if an AppX Provisioned Package exist. Neccessary? Probably not.
#>

# Define an array of app names to check
$appNames = @(
    # "Microsoft.BingNews",
    # "Microsoft.BingWeather",
    # "Microsoft.GamingApp",
    # "Microsoft.Getstarted",
    # "Microsoft.GetHelp",
    # "Microsoft.Messaging",
    # "Microsoft.MicrosoftSolitaireCollection",
    # "Microsoft.People",
    # "Microsoft.Windows.Photos",
    # "Microsoft.windowscommunicationsapps",
    # "Microsoft.WindowsFeedbackHub",
    # "Microsoft.WindowsMaps",
    # "Microsoft.Xbox.TCUI",
    # "Microsoft.XboxGameCallableUI",
    # "Microsoft.XboxGameOverlay",
    # "Microsoft.XboxGamingOverlay",
    # "Microsoft.XboxIdentityProvider",
    # "Microsoft.XboxSpeechToTextOverlay",
    # "Microsoft.YourPhone",
    # "Microsoft.ZuneMusic",
    # "Microsoft.ZuneVideo",
    # "MicrosoftTeams",
    # "Mozilla Firefox (x64 en-US)",
    # "Notepad++.Notepad++",
    # "Notepad++ (64-bit x64)",
    # "InstEd 1.5.15.26",
    # "Citrix Workspace",
    # "BCR Plug-in",
    # "7-zip 24.08 (x64)"
)

# Set debug mode
$DebugMode = $false

# Set timeout for uninstall operations (in seconds)
$UninstallTimeout = 90

# Function to log events
function Log-Event {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage
    Add-Content -Path "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\RemoveUnwantedApps.log" -Value $logMessage
}

# Function to check if an app is installed using winget
function Is-WingetAppInstalled {
    param (
        [string]$appName
    )
    Log-Event "DEBUG: Checking if winget app is installed with Name: $appName"
    $app = winget list --name $appName -q | Select-String -Pattern $appName
    return $app -ne $null
}

# Function to check if an AppX Provisioned Package is installed
function Is-AppXProvisionedPackageInstalled {
    param (
        [string]$appName
    )
    $package = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName }
    return $package -ne $null
}

# Function to check if an AppX Package is installed
function Is-AppXPackageInstalled {
    param (
        [string]$appName
    )
    $apps = Get-AppxPackage -AllUsers -Name $appName -ErrorAction SilentlyContinue
    $uniqueApps = $apps | Select-Object -Unique
    return $uniqueApps -ne $null
}

# Function to check if a Win32 App is installed
function Is-Win32AppInstalled {
    param (
        [string]$appName
    )
    $appPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Ensure the registry provider is loaded
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    $userSIDs = Get-ChildItem -Path "HKU:\" | Select-Object -ExpandProperty PSChildName

    foreach ($userSID in $userSIDs) {
        $appPaths += "HKU:\$userSID\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    foreach ($path in $appPaths) {
        $apps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $appName }
        if ($apps) {
            return $true
        }
    }
    return $false
}

# Function to uninstall an app using winget
function Uninstall-WingetApp {
    param (
        [string]$appId
    )
    if ($DebugMode) {
        Log-Event "DEBUG: Would uninstall winget app: $appId"
        return $true
    } else {
        $uninstallResult = Start-Process -FilePath "winget" -ArgumentList "uninstall --accept-source-agreements --disable-interactivity --id $appId" -NoNewWindow -Wait -PassThru -ErrorAction Stop 2>&1
        if ($uninstallResult) {
            Log-Event "$appId uninstalled successfully using winget."
            return $true
        } else {
            Log-Event "Failed to uninstall $appId using winget."
            return $false
        }
    }
}

# Function to uninstall an AppX Provisioned Package
function Uninstall-AppXProvisionedPackage {
    param (
        [string]$appName
    )
    $package = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName }
    if ($package) {
        if ($DebugMode) {
            Log-Event "DEBUG: Would uninstall provisioned package: $appName"
        } else {
            Log-Event "Executing: Remove-AppxProvisionedPackage -Online -PackageName $($package.PackageName) -ErrorAction Stop"
            $output = Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop 2>&1
            Log-Event "Output: $output"
            Log-Event "Uninstalled provisioned package: $appName"
        }
    }
}

# Function to uninstall an AppX Package
function Uninstall-AppxPackage {
    param (
        [string]$appName
    )
    if ($DebugMode) {
        Log-Event "DEBUG: Would uninstall AppX Package: $appName"
    } else {
        Log-Event "Executing: Get-AppxPackage -Name $appName | Remove-AppxPackage -AllUsers -ErrorAction Stop"
        $output = Get-AppxPackage -Name $appName | Remove-AppxPackage -AllUsers -ErrorAction Stop 2>&1
        Log-Event "Output: $output"
        Log-Event "Uninstalled AppX Package: $appName"
    }
}

# Function to uninstall a Win32 App
function Uninstall-Win32App {
    param (
        [string]$appName
    )
    $appPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Ensure the registry provider is loaded
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    $userSIDs = Get-ChildItem -Path "HKU:\" | Select-Object -ExpandProperty PSChildName

    foreach ($userSID in $userSIDs) {
        $appPaths += "HKU:\$userSID\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $appPaths += "HKU:\$userSID\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    foreach ($path in $appPaths) {
        $apps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $appName }
        foreach ($app in $apps) {
            $uninstallString = $null
            $uninstallArgs = ""
            if ($app.QuietUninstallString) {
                $uninstallString = $app.QuietUninstallString
            } elseif ($app.UninstallString -and $app.UninstallString -match "(?i)msiexec") {
                $uninstallString = $app.UninstallString -replace "/I", "/X"
                $uninstallString = $uninstallString -replace "(?i)msiexe?c(\.exe)?", "$env:systemroot\system32\msiexec.exe"
                
                # Extract everything after msiexec or msiexec.exe
                if ($uninstallString -match "(?i)msiexe?c(\.exe)?\s+(?<args>.*)$") {
                    $uninstallArgs = $matches['args'] + " /qn /norestart"
                } else {
                    $uninstallArgs = " /qn /norestart"
                }
                $uninstallString = "$env:systemroot\system32\msiexec.exe $uninstallArgs"
            }
    
            if ($uninstallString) {
                if ($DebugMode) {
                    Log-Event "DEBUG: Would uninstall Win32 app: $appName using command: $uninstallString"
                } else {
                    Log-Event "Executing: $uninstallString"
                    if ($app.QuietUninstallString) {
                        $output = Start-Process -FilePath "$env:systemroot\system32\cmd.exe" -ArgumentList "/c $uninstallString" -NoNewWindow -Wait -PassThru -ErrorAction Stop 2>&1
                    } else {
                        $output = Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList $uninstallArgs -NoNewWindow -Wait -PassThru -ErrorAction Stop 2>&1
                    }
                    Log-Event "Output: $output"
                    Log-Event "Uninstalled Win32 App: $appName"
                }
            } else {
                Log-Event "No uninstall string found for $appName"
            }
        }
    }
}

# Loop through the array of app names
foreach ($appName in $appNames) {
    $isWingetAppInstalled = Is-WingetAppInstalled -appName $appName
    if ($isWingetAppInstalled -eq $true) {
        Uninstall-WingetApp -appId $appName
    } elseif (Is-AppXProvisionedPackageInstalled -appName $appName) {
        Uninstall-AppXProvisionedPackage -appName $appName
        # Check and uninstall AppX Package if it exists
        if (Is-AppXPackageInstalled -appName $appName) {
            Uninstall-AppxPackage -appName $appName
        }
    } elseif (Is-AppXPackageInstalled -appName $appName) {
        Uninstall-AppxPackage -appName $appName
    } elseif (Is-Win32AppInstalled -appName $appName) {
        Uninstall-Win32App -appName $appName
    } else {
        Log-Event "App not found: $appName"
    }
}