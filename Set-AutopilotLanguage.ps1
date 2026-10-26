#Requires -Version 5.1
# ============================================================
# Unified Autopilot Language and Time Zone Configuration
# Windows 11 / Intune Win32 / SYSTEM / 64-bit
#
# Languages: da-DK, fi-FI, nb-NO, sv-SE
# No changes when Autopilot specifies os-default
# On 25H2, discover display and optional language CABs by locale in Languages/
# Returns failure for incomplete installations so Intune can retry
# ============================================================

$ErrorActionPreference = "Stop"

# The Intune Management Extension can invoke 32-bit PowerShell. Re-enter native
# 64-bit PowerShell before touching registry, language or DISM state.
if (-not [Environment]::Is64BitProcess) {
    $NativePS = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $NativePS)) {
        throw 'Native 64-bit Windows PowerShell could not be found.'
    }
    & $NativePS -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

$LanguagesFolder = Join-Path $PSScriptRoot 'Languages'
$OSBuild = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber
$UseLocalCAB = ($OSBuild -eq 26200) # Windows 11 25H2; fail safely for unrecognized builds.
$InstallMethod = if ($UseLocalCAB) { 'LocalCAB' } else { 'Install-Language' }
$InstallError = '' 

$APPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot"
$APCachePath = "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache"
$RegPath = "HKLM:\SOFTWARE\COMPANY"
$LogFolder = "$env:ProgramData\COMPANY\Logs"
$LogFile = Join-Path $LogFolder "AutopilotLanguage.log"

$Countries = @{
    "da-DK" = @{ GeoId = 61;  Name = "Denmark"; TimeZone = "Romance Standard Time" }
    "fi-FI" = @{ GeoId = 77;  Name = "Finland"; TimeZone = "FLE Standard Time" }
    "nb-NO" = @{ GeoId = 177; Name = "Norway"; TimeZone = "W. Europe Standard Time" }
    "sv-SE" = @{ GeoId = 221; Name = "Sweden"; TimeZone = "W. Europe Standard Time" }
}

$ConfiguredLanguage = "unknown"
$ConfiguredTimeZone = "unknown"
$TimeZoneStatus = "NotAttempted"
$Status = "ProfileUnavailable"
$Processed = $false
$Failures = 0

function Write-Log {
    param([string]$Message)

    try {
        $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
        Add-Content -Path $LogFile -Value $Line -ErrorAction Stop
    }
    catch {}
}

function Invoke-SafeStep {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        Write-Log "START: $Name"
        & $Action
        Write-Log "SUCCESS: $Name"
        return $true
    }
    catch {
        $script:Failures++
        Write-Log "FAILED: $Name - $($_.Exception.Message)"
        return $false
    }
}

try {
    # --------------------------------------------------------
    # 1. Prepare logging and registry
    # --------------------------------------------------------

    New-Item -Path $LogFolder -ItemType Directory `
        -Force -ErrorAction Stop | Out-Null

    New-Item -Path $RegPath -Force `
        -ErrorAction Stop | Out-Null

    Write-Log "=========================================="
    Write-Log "Starting Autopilot language setup"
    Write-Log "OS build: $OSBuild; installation method: $InstallMethod"
    Write-Log "Language package folder: $LanguagesFolder"

    # --------------------------------------------------------
    # 2. Read Autopilot deployment profile values
    # --------------------------------------------------------

    $APLanguage = ""
    $APRegion = ""

    if (Test-Path $APPath) {
        $AP = Get-ItemProperty -Path $APPath -ErrorAction Stop

        $APLanguage = ([string]$AP.CloudAssignedLanguage).Trim()
        $APRegion = ([string]$AP.CloudAssignedRegion).Trim()
    }

    $APSource = "Diagnostics"
    Write-Log "Diagnostics CloudAssignedLanguage: $APLanguage"
    Write-Log "Diagnostics CloudAssignedRegion: $APRegion"

    # Fall back to the downloaded Autopilot policy JSON when diagnostic
    # values are absent. Do not override explicit os-default instructions.
    if ([string]::IsNullOrWhiteSpace($APLanguage) -or
        [string]::IsNullOrWhiteSpace($APRegion)) {
        try {
            $Cache = Get-ItemProperty -Path $APCachePath -Name PolicyJsonCache -ErrorAction Stop
            $CacheJson = [string]$Cache.PolicyJsonCache
            if (-not [string]::IsNullOrWhiteSpace($CacheJson)) {
                $Policy = $CacheJson | ConvertFrom-Json -ErrorAction Stop
                $CacheLanguage = ([string]$Policy.CloudAssignedLanguage).Trim()
                $CacheRegion = ([string]$Policy.CloudAssignedRegion).Trim()
                Write-Log "Cache CloudAssignedLanguage: $CacheLanguage"
                Write-Log "Cache CloudAssignedRegion: $CacheRegion"
                if ([string]::IsNullOrWhiteSpace($APLanguage) -and
                    -not [string]::IsNullOrWhiteSpace($CacheLanguage)) {
                    $APLanguage = $CacheLanguage
                    $APSource = "PolicyJsonCache"
                }
                if ([string]::IsNullOrWhiteSpace($APRegion) -and
                    -not [string]::IsNullOrWhiteSpace($CacheRegion)) {
                    $APRegion = $CacheRegion
                    $APSource = "PolicyJsonCache"
                }
                if ($Policy.PSObject.Properties.Name -contains 'PolicyDownloadDate') {
                    Write-Log "Cache PolicyDownloadDate: $($Policy.PolicyDownloadDate)"
                }
            }
        }
        catch {
            Write-Log "Autopilot policy cache unavailable: $($_.Exception.Message)"
        }
    }

    Write-Log "Autopilot policy source: $APSource"
    Write-Log "Effective CloudAssignedLanguage: $APLanguage"
    Write-Log "Effective CloudAssignedRegion: $APRegion"

    # --------------------------------------------------------
    # 3. Handle os-default - DO NOT CHANGE ANY SETTINGS
    # --------------------------------------------------------

    if (
        $APLanguage -ieq "os-default" -or
        $APRegion -ieq "os-default"
    ) {
        $ConfiguredLanguage = "os-default"
        $ConfiguredTimeZone = "os-default"
        $TimeZoneStatus = "OSDefault"
        $Status = "OSDefault"

        Write-Log "OS default detected. No changes performed."
    }

    # --------------------------------------------------------
    # 4. Handle missing Autopilot language
    # --------------------------------------------------------

    elseif ([string]::IsNullOrWhiteSpace($APLanguage)) {
        $ConfiguredLanguage = "unknown"
        $Status = "ProfileUnavailable"

        Write-Log "No Autopilot language detected. Skipping."
    }

    # --------------------------------------------------------
    # 5. Handle unsupported language
    # --------------------------------------------------------

    elseif (-not $Countries.ContainsKey($APLanguage)) {
        $ConfiguredLanguage = $APLanguage
        $Status = "Unsupported"

        Write-Log "Unsupported language: $APLanguage"
        Write-Log "No Windows settings will be changed."
    }

    # --------------------------------------------------------
    # 6. Configure supported country
    # --------------------------------------------------------

    else {
        $Language = $APLanguage
        $Country = $Countries[$Language]
        $GeoId = [int]$Country.GeoId
        $TimeZone = [string]$Country.TimeZone

        $ConfiguredLanguage = $Language
        $ConfiguredTimeZone = $TimeZone

        Write-Log "Selected country: $($Country.Name)"
        Write-Log "Language: $Language"
        Write-Log "GeoId: $GeoId"
        Write-Log "Time zone: $TimeZone"

        # Configure time zone independently of language pack download.
        # This still runs if language installation later fails.
        $TimeZoneOK = Invoke-SafeStep "Time zone" {
            $CurrentTimeZone = (Get-TimeZone -ErrorAction Stop).Id
            if ($CurrentTimeZone -ne $TimeZone) {
                Set-TimeZone -Id $TimeZone -ErrorAction Stop
            }
            $ActualTimeZone = (Get-TimeZone -ErrorAction Stop).Id
            if ($ActualTimeZone -ne $TimeZone) {
                throw "Time zone verification failed. Actual: $ActualTimeZone"
            }
        }
        $TimeZoneStatus = if ($TimeZoneOK) { "Completed" } else { "Failed" }

        # Install missing language resources.
        # Do not continue changing Windows settings if
        # language installation cannot be established.

        $LanguageReady = Invoke-SafeStep "Language installation" {
            Import-Module LanguagePackManagement -ErrorAction Stop

            $Installed = Get-InstalledLanguage -Language $Language -ErrorAction Stop
            if ($UseLocalCAB) {
                # Discover known language CAB types for the requested locale only.
                # This is deliberately NOT a generic installation of arbitrary CABs.
                # Example: Speech-en-us is ignored when the target is sv-SE.
                $LocaleFile = $Language.ToLowerInvariant()
                if (-not (Test-Path -LiteralPath $LanguagesFolder -PathType Container)) {
                    throw "Language CAB folder not found: $LanguagesFolder"
                }
                $AllCABs = @(Get-ChildItem -LiteralPath $LanguagesFolder -Filter '*.cab' -File -ErrorAction Stop)
                $DisplayName = "Microsoft-Windows-Client-Language-Pack_x64_$LocaleFile.cab"
                $DisplayCAB = @($AllCABs | Where-Object { $_.Name -ieq $DisplayName }) | Select-Object -First 1

                $FeatureOrder = @('Basic', 'Handwriting', 'OCR', 'TextToSpeech', 'Speech')
                $FeatureCABs = @{}
                foreach ($Feature in $FeatureOrder) {
                    $Prefix = "Microsoft-Windows-LanguageFeatures-$Feature-$LocaleFile-Package~"
                    $MatchingCABs = @($AllCABs | Where-Object {
                        $_.Name.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase) -and
                        $_.Name -match '(?i)~amd64~~(?:[\d\.]+)?\.cab$'
                    })
                    if ($MatchingCABs.Count -gt 1) {
                        throw "Multiple $Feature CABs found for $Language; remove duplicates: $($MatchingCABs.Name -join ', ')"
                    }
                    if ($MatchingCABs.Count -eq 1) { $FeatureCABs[$Feature] = $MatchingCABs[0] }
                }

                $FoundNames = @()
                if ($DisplayCAB) { $FoundNames += $DisplayCAB.Name }
                foreach ($Feature in $FeatureOrder) {
                    if ($FeatureCABs.ContainsKey($Feature)) { $FoundNames += $FeatureCABs[$Feature].Name }
                }
                Write-Log "Matched $($FoundNames.Count) local CAB(s) for ${Language}: $($FoundNames -join ', ')"

                function Invoke-DismPackage {
                    param([string]$Path, [string]$Description)
                    Write-Log "DISM installing $Description from $Path"
                    $DismOutput = & "$env:WINDIR\System32\dism.exe" /Online /Add-Package "/PackagePath:$Path" /NoRestart 2>&1
                    $Exit = $LASTEXITCODE
                    foreach ($Line in $DismOutput) { Write-Log "DISM: $Line" }
                    if ($Exit -notin @(0,3010,1641)) {
                        throw "DISM $Description failed with exit code $Exit."
                    }
                    if ($Exit -in @(3010,1641)) { Write-Log "DISM requested reboot for $Description" }
                }

                # The display language pack goes first; Basic precedes other FODs.
                if (-not $Installed) {
                    if (-not $DisplayCAB) { throw "Required display-language CAB missing: $DisplayName" }
                    Invoke-DismPackage -Path $DisplayCAB.FullName -Description "display language $Language"
                }
                else { Write-Log "Display language $Language already installed." }

                $BasicName = "Language.Basic~~~$Language~0.0.1.0"
                $Basic = Get-WindowsCapability -Online -Name $BasicName -ErrorAction Stop
                if ($Basic.State -ne 'Installed' -and -not $FeatureCABs.ContainsKey('Basic')) {
                    throw "Required Basic CAB missing for $Language"
                }

                foreach ($Feature in $FeatureOrder) {
                    if (-not $FeatureCABs.ContainsKey($Feature)) { continue }
                    $CapabilityName = "Language.$Feature~~~$Language~0.0.1.0"
                    $Capability = Get-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop
                    if ($Capability.State -eq 'Installed') {
                        Write-Log "$Feature capability for $Language already installed; skipping."
                        continue
                    }
                    # Language FODs are non-satellite CABs. /Add-Package works for
                    # these individually, though Microsoft prefers /Add-Capability
                    # from a correctly constructed FOD repository.
                    Invoke-DismPackage -Path $FeatureCABs[$Feature].FullName -Description "$Feature capability $Language"
                    $Capability = Get-WindowsCapability -Online -Name $CapabilityName -ErrorAction Stop
                    if ($Capability.State -ne 'Installed') {
                        throw "$Feature capability verification failed for $Language; state: $($Capability.State)"
                    }
                }

                $Basic = Get-WindowsCapability -Online -Name $BasicName -ErrorAction Stop
                if ($Basic.State -ne 'Installed') {
                    throw "Basic language capability not installed; actual state: $($Basic.State)."
                }
            }
            else {
                if (-not $Installed) {
                    Write-Log "Installing missing language online: $Language"
                    Install-Language -Language $Language -CopyToSettings -ErrorAction Stop | Out-Null
                }
                else { Write-Log "Language already installed; no download needed." }
            }

            $Installed = Get-InstalledLanguage -Language $Language -ErrorAction Stop
            if (-not $Installed) {
                throw "Display language $Language not detected after installation."
            }
        }

        if (-not $LanguageReady) {
            $Status = "LanguageInstallFailed"
            Write-Log "Skipping remaining Windows configuration."
        }
        else {
            # System Windows display language
            $SystemOK = Invoke-SafeStep "System UI language" {
                Set-SystemPreferredUILanguage `
                    -Language $Language -ErrorAction Stop
            }

            # Language and keyboard defaults for executing account
            $ListOK = Invoke-SafeStep "Language list" {
                $List = New-WinUserLanguageList `
                    -Language $Language -ErrorAction Stop

                Set-WinUserLanguageList `
                    -LanguageList $List `
                    -Force -ErrorAction Stop
            }

            # Display language override
            $UIOK = Invoke-SafeStep "UI language override" {
                Set-WinUILanguageOverride `
                    -Language $Language -ErrorAction Stop
            }

            # Regional formatting
            $CultureOK = Invoke-SafeStep "Regional formatting" {
                Set-Culture `
                    -CultureInfo $Language -ErrorAction Stop
            }

            # Home country
            $GeoOK = Invoke-SafeStep "Home location" {
                Set-WinHomeLocation `
                    -GeoId $GeoId -ErrorAction Stop
            }

            # Copy settings only when source settings succeeded.
            # Avoid copying partially configured SYSTEM defaults.

            if ($SystemOK -and $ListOK -and $UIOK -and
                $CultureOK -and $GeoOK) {

                $CopyOK = Invoke-SafeStep "Copy settings to system" {
                    Copy-UserInternationalSettingsToSystem `
                        -WelcomeScreen $true `
                        -NewUser $true `
                        -ErrorAction Stop
                }
            }
            else {
                Write-Log "Skipping copy due to incomplete settings."
            }

            if ($Failures -eq 0) {
                $Status = "Completed"
            }
            else {
                $Status = "Partial"
            }
        }
    }
}
catch {
    Write-Log "Unexpected error: $($_.Exception.Message)"
    $Status = "Failed"
    $Failures++
}
finally {
    # --------------------------------------------------------
    # 7. Save result for detection and future remediation
    # --------------------------------------------------------

    try {
        New-Item -Path $RegPath -Force `
            -ErrorAction Stop | Out-Null

        # Write informational values first.
        New-ItemProperty -Path $RegPath `
            -Name "ConfiguredLanguage" `
            -Value $ConfiguredLanguage `
            -PropertyType String -Force `
            -ErrorAction Stop | Out-Null

        New-ItemProperty -Path $RegPath `
            -Name "ConfiguredTimeZone" `
            -Value $ConfiguredTimeZone `
            -PropertyType String -Force `
            -ErrorAction Stop | Out-Null

        New-ItemProperty -Path $RegPath `
            -Name "TimeZoneConfigurationStatus" `
            -Value $TimeZoneStatus `
            -PropertyType String -Force `
            -ErrorAction Stop | Out-Null

        New-ItemProperty -Path $RegPath `
            -Name "LanguageConfigurationStatus" `
            -Value $Status `
            -PropertyType String -Force `
            -ErrorAction Stop | Out-Null

        New-ItemProperty -Path $RegPath `
            -Name "LanguageConfigurationDate" `
            -Value (Get-Date -Format "yyyy-MM-ddTHH:mm:ss") `
            -PropertyType String -Force `
            -ErrorAction Stop | Out-Null

        # Write detection marker LAST. Only successful configuration qualifies.
        $DetectionSuccess = ($Status -in @('Completed', 'OSDefault'))
        New-ItemProperty -Path $RegPath `
            -Name "LanguageInstallationMethod" `
            -Value $InstallMethod `
            -PropertyType String -Force `
            -ErrorAction Stop | Out-Null

        New-ItemProperty -Path $RegPath `
            -Name "LanguageConfigurationProcessed" `
            -Value ([int]$DetectionSuccess) `
            -PropertyType DWord -Force `
            -ErrorAction Stop | Out-Null

        $Processed = $DetectionSuccess
    }
    catch {
        Write-Log "Registry write failed: $($_.Exception.Message)"
    }

    Write-Log "Final language: $ConfiguredLanguage"
    Write-Log "Target time zone: $ConfiguredTimeZone"
    Write-Log "Time zone status: $TimeZoneStatus"
    Write-Log "Final status: $Status"
    Write-Log "Registry processed: $Processed"
    Write-Log "Configuration attempt finished"
    Write-Log "=========================================="
}

# Required Win32 app: return a failure when Windows wasn't fully configured.
# For a non-blocking Autopilot deployment, do not select this app as ESP-blocking.
if ($Status -in @('Completed', 'OSDefault') -and $Processed) { exit 0 }
exit 1