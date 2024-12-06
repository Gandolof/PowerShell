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
        if ($apps) {
            foreach ($app in $apps) {
                if ($app.PSChildName -match '^\{[0-9a-fA-F\-]+\}$') {
                    # If the path is a GUID, use msiexec
                    if ($DebugMode) {
                        Log-Event "DEBUG: Would uninstall Win32 app using msiexec: $appName"
                    } else {
                        Log-Event "Found Win32 app to uninstall: $appName"
                        Log-Event "Executing: Start-Process -FilePath msiexec.exe -ArgumentList /x $($app.PSChildName) /quiet /norestart -Wait"
                        $job = Start-Job -ScriptBlock {
                            param ($app)
                            Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $($app.PSChildName) /quiet /norestart" -Wait
                        } -ArgumentList $app
                        if (Wait-Job -Job $job -Timeout $UninstallTimeout) {
                            $output = Receive-Job -Job $job
                            Log-Event "Output: $output"
                            Log-Event "Uninstalled Win32 app: $appName"
                        } else {
                            Log-Event "Uninstall of Win32 app $appName timed out."
                            Stop-Job -Job $job
                        }
                    }
                } elseif ($app.QuietUninstallString) {
                    # If QuietUninstallString is available, use it
                    if ($DebugMode) {
                        Log-Event "DEBUG: Would uninstall Win32 app using QuietUninstallString: $appName"
                    } else {
                        Log-Event "Found Win32 app to uninstall: $appName"
                        Log-Event "Executing: Start-Process -FilePath cmd.exe -ArgumentList /c $($app.QuietUninstallString) -Wait"
                        $job = Start-Job -ScriptBlock {
                            param ($app)
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($app.QuietUninstallString)" -Wait
                        } -ArgumentList $app
                        if (Wait-Job -Job $job -Timeout $UninstallTimeout) {
                            $output = Receive-Job -Job $job
                            Log-Event "Output: $output"
                            Log-Event "Uninstalled Win32 app: $appName"
                        } else {
                            Log-Event "Uninstall of Win32 app $appName timed out."
                            Stop-Job -Job $job
                        }
                    }
                } else {
                    Log-Event "Unable to uninstall Win32 app: $appName. QuietUninstallString not found."
                }
            }
        }
    }
}


function Is-WingetAppInstalled {
    param (
        [string]$appName
    )
    Log-Event "DEBUG: Checking if winget app is installed with Name: $appName"
    $app = winget list --name $appName -q | Select-String -Pattern $appName
    if ($app) {
        Log-Event "DEBUG: Found winget app with Name: $appName"
        return $true
    } else {
        Log-Event "DEBUG: No winget app found with Name: $appName"
        return $false
    }
}