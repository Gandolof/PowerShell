#requires -Version 5.1
<#!
.SYNOPSIS
Exports an Intune inventory for Windows, macOS, iOS/iPadOS and Android, including platform-specific fields.
.NOTES
Requires Microsoft.Graph.Authentication; runs read-only. Endpoint Analytics and device health reports
may not contain every Windows device. A missing report value is not evidence of a disabled feature.
Only Intune-managed records are included; unmanaged Entra devices are outside the scope.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) ('Intune-All-Platforms-Inventory-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [string]$TenantId,
    [switch]$SkipPerDeviceDetails
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Install the authentication module first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
Import-Module Microsoft.Graph.Authentication
$scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementServiceConfig.Read.All', 'DeviceManagementConfiguration.Read.All')
$connect = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect | Out-Null

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Uri) {
        $result = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        foreach ($item in @($result.value)) { if ($null -ne $item) { $items.Add($item) } }
        $Uri = $result.'@odata.nextLink'
    }
    return $items.ToArray()
}
function Get-PropertyValue {
    param($Object, [string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        $prop = $Object.PSObject.Properties[$n]
        if ($prop -and $null -ne $prop.Value -and "$($prop.Value)" -ne '') { return $prop.Value }
        if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($n) -and $null -ne $Object[$n] -and "$($Object[$n])" -ne '') { return $Object[$n] }
    }
    return $null
}
function Format-Status($value) {
    if ($null -eq $value -or "$value" -eq '') { return 'Unknown' }
    switch -Regex ("$value".Trim().ToLowerInvariant()) {
        '^(true|1|enabled|on|pass|passed|healthy)$' { return 'Enabled' }
        '^(false|0|disabled|off|fail|failed|unhealthy)$' { return 'Disabled' }
        default { return "$value" }
    }
}
function Get-ReportRows {
    param([Parameter(Mandatory)][string]$ReportName)
    $temp = Join-Path ([IO.Path]::GetTempPath()) ('graph-report-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        $body = @{ reportName = $ReportName; format = 'csv' } | ConvertTo-Json -Compress
        $job = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs' -Body $body -ContentType 'application/json' -OutputType PSObject
        $id = [uri]::EscapeDataString([string]$job.id)
        $deadline = (Get-Date).AddMinutes(10)
        do {
            Start-Sleep -Seconds 3
            $job = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$id')" -OutputType PSObject
            if ($job.status -eq 'failed') { throw "Report job $ReportName failed" }
        } until ($job.status -eq 'completed' -or $job.status -eq 'complete' -or (Get-Date) -gt $deadline)
        if ($job.status -notin @('completed','complete')) { throw "Report job $ReportName timed out (status $($job.status))" }
        if (-not $job.url) { throw "Report job $ReportName had no download URL" }
        $zip = Join-Path $temp 'report.zip'
        Invoke-WebRequest -Uri $job.url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $temp -Force
        $csv = @(Get-ChildItem -Path $temp -Filter '*.csv' -Recurse -File | Select-Object -First 1)
        if (-not $csv) { throw "Report job $ReportName contained no CSV" }
        return @(Import-Csv -LiteralPath $csv[0].FullName)
    }
    finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}
function Add-IndexRow {
    param([hashtable]$Index, $Row, [string[]]$Keys)
    foreach ($key in $Keys) {
        $value = Get-PropertyValue $Row @($key)
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { $Index[([string]$value).Trim().ToLowerInvariant()] = $Row }
    }
}
function Find-IndexRow {
    param([hashtable]$Index, [string[]]$Keys)
    foreach ($key in $Keys) {
        if ($key -and $Index.ContainsKey($key.Trim().ToLowerInvariant())) { return $Index[$key.Trim().ToLowerInvariant()] }
    }
    return $null
}

Write-Host 'Reading Intune managed devices...'
$devices = @(Get-GraphCollection 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=100') | Where-Object { $_.operatingSystem -match '^(Windows|macOS|MacMDM|iOS|iPadOS|Android|AndroidForWork)$' }
Write-Host "Found $($devices.Count) cross-platform device(s)."

$autopilotIndex = @{}
try {
    Write-Host 'Reading Windows Autopilot identities...'
    $autopilot = @(Get-GraphCollection 'https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$top=100')
    foreach ($a in $autopilot) { Add-IndexRow $autopilotIndex $a @('managedDeviceId','azureActiveDirectoryDeviceId','serialNumber') }
    Write-Host "Found $($autopilot.Count) Autopilot identities."
} catch { Write-Warning "Autopilot query failed: $_. Registration will be Unknown."; $autopilotIndex = $null }

$readinessIndex = @{}
try {
    Write-Host 'Downloading Work from anywhere report...'
    foreach ($r in @(Get-ReportRows 'WorkFromAnywhereDeviceList')) { Add-IndexRow $readinessIndex $r @('DeviceId','ReferenceId','SerialNumber') }
    Write-Host "Indexed $($readinessIndex.Count) readiness identifiers."
} catch { Write-Warning "Readiness report unavailable: $_. Readiness will be Unknown." }

$healthIndex = @{}
try {
    Write-Host 'Downloading Windows device health attestation report...'
    foreach ($r in @(Get-ReportRows 'WindowsDeviceHealthAttestationReport')) { Add-IndexRow $healthIndex $r @('DeviceId') }
    Write-Host "Indexed $($healthIndex.Count) health identifiers."
} catch { Write-Warning "Health attestation report unavailable: $_. Secure Boot will be Unknown." }

$rows = [System.Collections.Generic.List[object]]::new()
$count = 0
foreach ($d in $devices) {
    $count++
    Write-Progress -Activity 'Building cross-platform inventory' -Status "$count / $($devices.Count): $($d.deviceName)" -PercentComplete ([math]::Round(100 * $count / [math]::Max(1,$devices.Count)))
    $rawOS = [string]$d.operatingSystem
    $platform = switch -Regex ($rawOS) {
        '^Windows$' { 'Windows'; break }
        '^(macOS|MacMDM)$' { 'macOS'; break }
        '^(iOS|iPadOS)$' { 'iOS/iPadOS'; break }
        '^(Android|AndroidForWork)$' { 'Android'; break }
        default { $rawOS }
    }
    $isWindowsDevice = ($platform -eq 'Windows')
    $hw = $null
    $primary = $null
    if (-not $SkipPerDeviceDetails) {
        try {
            $detail = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($d.id)?`$select=id,hardwareInformation" -OutputType PSObject
            $hw = $detail.hardwareInformation
        } catch { Write-Warning "Hardware details unavailable for $($d.deviceName): $_" }
        try {
            $users = @(Get-GraphCollection "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($d.id)/users")
            if ($users.Count -gt 0) { $primary = Get-PropertyValue $users[0] @('userPrincipalName','mail') }
        } catch { Write-Warning "Primary user unavailable for $($d.deviceName): $_" }
    }
    $ap = if ($isWindowsDevice -and $null -ne $autopilotIndex) { Find-IndexRow $autopilotIndex @([string]$d.id,[string]$d.azureADDeviceId,[string]$d.serialNumber) } else { $null }
    $ready = if ($isWindowsDevice) { Find-IndexRow $readinessIndex @([string]$d.id,[string]$d.azureADDeviceId,[string]$d.serialNumber) } else { $null }
    $health = if ($isWindowsDevice) { Find-IndexRow $healthIndex @([string]$d.id,[string]$d.azureADDeviceId) } else { $null }
    $osVersion = [string]$d.osVersion
    $build = if ($osVersion -match '^\d+\.\d+\.(\d+)') { [int]$Matches[1] } else { $null }
    $family = if (-not $isWindowsDevice) { $null } elseif ($null -eq $build) { 'Unknown' } elseif ($build -ge 22000) { 'Windows 11' } elseif ($build -ge 10240) { 'Windows 10' } else { 'Unknown' }
    $tpm = if ($isWindowsDevice) { Get-PropertyValue $hw @('tpmSpecificationVersion','tpmVersion') } else { $null }
    if (-not $tpm) { $tpm = Get-PropertyValue $health @('TpmVersion') }
    $secureBoot = if ($isWindowsDevice) { Get-PropertyValue $health @('SecureBootStatus') } else { $null }
    $eligibility = Get-PropertyValue $ready @('UpgradeEligibility')
    $blockers = @()
    foreach ($col in @('TPMCheckFailed','SecureBootCheckFailed','RamCheckFailed','StorageCheckFailed','Processor64BitCheckFailed','ProcessorCoreCountCheckFailed','ProcessorFamilyCheckFailed','ProcessorSpeedCheckFailed','OSCheckFailed')) {
        $value = Get-PropertyValue $ready @($col)
        if ("$value" -match '^(?i:true|1|yes)$') { $blockers += ($col -replace 'CheckFailed$','') }
    }
    $storageTotal = Get-PropertyValue $d @('totalStorageSpaceInBytes')
    $storageFree = Get-PropertyValue $d @('freeStorageSpaceInBytes')
    $storageGb = if ($null -ne $storageTotal) { [math]::Round([double]$storageTotal / 1GB, 2) } else { $null }
    $freeGb = if ($null -ne $storageFree) { [math]::Round([double]$storageFree / 1GB, 2) } else { $null }
    $rows.Add([pscustomobject][ordered]@{
        'Platform'                   = $platform
        'Reported OS'                = $rawOS
        'Device Name'                = $d.deviceName
        'Serial Number'              = $d.serialNumber
        'Primary User'               = if ($primary) { $primary } else { 'Unknown' }
        'Enrolled User'              = $d.userPrincipalName
        'Manufacturer'               = $d.manufacturer
        'Model'                      = $d.model
        'OS Version'                 = $osVersion
        'OS Family'                  = if ($isWindowsDevice) { $family } else { $platform }
        'Windows Family'             = $family
        'Windows Edition'            = if ($isWindowsDevice -and $hw) { Get-PropertyValue $hw @('operatingSystemEdition') } else { $null }
        'Windows Version (Build)'    = if ($isWindowsDevice) { $osVersion } else { $null }
        'OS Build'                   = if ($isWindowsDevice) { $build } else { $null }
        'Autopilot Registered'       = if (-not $isWindowsDevice) { 'Not applicable' } elseif ($null -eq $autopilotIndex) { 'Unknown' } elseif ($ap) { 'Yes' } else { 'No' }
        'Autopilot Group Tag'        = if ($ap) { $ap.groupTag } else { $null }
        'Autopilot Enrollment State' = if ($ap) { $ap.enrollmentState } else { $null }
        'Windows 11 Readiness'       = if (-not $isWindowsDevice) { 'Not applicable' } elseif ($eligibility) { $eligibility } else { 'Unknown' }
        'Windows 11 Blockers'        = ($blockers -join '; ')
        'TPM Version'                = if (-not $isWindowsDevice) { 'Not applicable' } elseif ($tpm) { $tpm } else { 'Unknown' }
        'TPM Enabled'                = if ($isWindowsDevice) { 'Unknown (not directly reported)' } else { 'Not applicable' }
        'TPM Requirement Failed'     = if ($ready) { Get-PropertyValue $ready @('TPMCheckFailed') } else { $null }
        'Secure Boot Attestation'    = if ($isWindowsDevice) { Format-Status $secureBoot } else { 'Not applicable' }
        'Secure Boot Enabled'        = if (-not $isWindowsDevice) { 'Not applicable' } elseif ("$secureBoot" -match '^(?i:true|1|enabled)$') { 'Yes (attested)' } else { 'Unknown (attestation not conclusive)' }
        'Secure Boot Requirement Failed' = if ($ready) { Get-PropertyValue $ready @('SecureBootCheckFailed') } else { $null }
        'Compliance State'           = $d.complianceState
        'Management Agent'           = $d.managementAgent
        'Enrollment Type'            = $d.deviceEnrollmentType
        'Ownership'                  = $d.managedDeviceOwnerType
        'Enrolled Date'              = $d.enrolledDateTime
        'Device Category'            = $d.deviceCategoryDisplayName
        'Entra Registration State'   = $d.deviceRegistrationState
        'Encryption Enabled'         = Get-PropertyValue $d @('isEncrypted')
        'Supervised (Apple)'         = if ($platform -in @('macOS','iOS/iPadOS')) { Get-PropertyValue $d @('isSupervised') } else { $null }
        'Activation Lock Bypass Code Present' = if ($platform -in @('macOS','iOS/iPadOS')) { Get-PropertyValue $d @('activationLockBypassCode') | ForEach-Object { if ($_) { 'Bypass code present' } } } else { $null }
        'Jailbroken or Rooted'       = if ($platform -in @('iOS/iPadOS','Android')) { Get-PropertyValue $d @('jailBroken') } else { $null }
        'Android Security Patch'     = if ($platform -eq 'Android') { $d.androidSecurityPatchLevel } else { $null }
        'IMEI'                       = if ($platform -in @('Android','iOS/iPadOS')) { $d.imei } else { $null }
        'MEID'                       = if ($platform -in @('Android','iOS/iPadOS')) { $d.meid } else { $null }
        'Phone Number'               = if ($platform -in @('Android','iOS/iPadOS')) { $d.phoneNumber } else { $null }
        'Carrier'                    = if ($platform -in @('Android','iOS/iPadOS')) { $d.subscriberCarrier } else { $null }
        'Wi-Fi MAC Address'          = $d.wiFiMacAddress
        'Total Storage GB'           = $storageGb
        'Free Storage GB'            = $freeGb
        'Last Intune Check-in'       = $d.lastSyncDateTime
        'Intune Device ID'           = $d.id
        'Entra Device ID'            = $d.azureADDeviceId
    })
}
Write-Progress -Activity 'Building cross-platform inventory' -Completed
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($rows.Count) managed devices to $OutputPath" -ForegroundColor Green
