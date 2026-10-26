
#Requires -Version 5.1
<#
.SYNOPSIS
    Export Intune policies and scripts to CSV.

.DESCRIPTION
    Read-only inventory of:
    - Modern configuration policies / Settings Catalog
    - Classic device configuration profiles
    - Classic and modern compliance policies
    - Windows PowerShell scripts and Remediations
    - macOS scripts and custom attributes
    - Android/iOS managed-device app configurations
    - Android/iOS managed-app configurations (MAM)
    - Android/iOS app protection policies

    Assignment groups are exported separately as:
    AssignedGroups and ExcludedGroups.

    User/device scope is NOT inferred from assignment groups.
#>

param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Intune-Inventory.csv')
)

$ErrorActionPreference = 'Stop'
$GraphBase = 'https://graph.microsoft.com/beta'

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

Connect-MgGraph -Scopes @(
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementScripts.Read.All'
    'DeviceManagementApps.Read.All'
    'Group.Read.All'
) -NoWelcome

$Results = [System.Collections.Generic.List[object]]::new()
$Errors = [System.Collections.Generic.List[string]]::new()
$GroupCache = @{}
$DefinitionCache = @{}

# ------------------------------------------------------------
# GRAPH FUNCTIONS
# ------------------------------------------------------------

function Invoke-Graph {
    param([string]$Uri)

    try {
        Invoke-MgGraphRequest -Method GET -Uri $Uri `
            -OutputType PSObject -ErrorAction Stop
    }
    catch {
        $Message = "$Uri :: $($_.Exception.Message)"
        $script:Errors.Add($Message)
        Write-Warning $Message
        $null
    }
}

function Get-GraphItems {
    param([string]$Uri)

    while ($Uri) {
        $Response = Invoke-Graph $Uri
        if ($null -eq $Response) { break }

        if ($null -ne $Response.value) {
            foreach ($Item in $Response.value) {
                if ($null -ne $Item) {
                    Write-Output $Item
                }
            }
        }

        $Uri = $Response.'@odata.nextLink'
    }
}

function Get-ValidId {
    param($Object)

    if ($null -eq $Object) { return $null }

    $Id = [string]$Object.id
    $Parsed = [guid]::Empty

    if ([guid]::TryParse($Id, [ref]$Parsed)) {
        return $Id
    }

    return $null
}

function Resolve-Group {
    param([string]$Id)

    if (-not $Id) { return '' }

    if ($script:GroupCache.ContainsKey($Id)) {
        return $script:GroupCache[$Id]
    }

    $Group = Invoke-Graph (
        "$GraphBase/groups/$Id" + '?$select=id,displayName'
    )

    $Name = if ($Group -and $Group.displayName) {
        [string]$Group.displayName
    }
    else {
        "Unresolved:$Id"
    }

    $script:GroupCache[$Id] = $Name
    return $Name
}

# ------------------------------------------------------------
# ASSIGNMENTS
# ------------------------------------------------------------

function Get-Assignments {
    param(
        [string]$Area,
        [string]$Endpoint,
        [string]$Id
    )

    $Included = [System.Collections.Generic.List[string]]::new()
    $Excluded = [System.Collections.Generic.List[string]]::new()
    $Targets = [System.Collections.Generic.List[string]]::new()
    $Filters = [System.Collections.Generic.List[string]]::new()

    $Uri = "$GraphBase/$Area/$Endpoint/$Id/assignments"
    $BeforeErrors = $script:Errors.Count

    $Assignments = @(Get-GraphItems $Uri)

    foreach ($Assignment in $Assignments) {
        $Target = $Assignment.target
        if (-not $Target) { continue }

        $Type = [string]$Target.'@odata.type'
        $GroupId = [string]$Target.groupId

        if (-not $GroupId) {
            $GroupId = [string]$Target.entraObjectId
        }

        if ($Type -match 'exclusionGroupAssignmentTarget' -or
            $Type -match 'excludeGroup') {

            if ($GroupId) {
                $Excluded.Add((Resolve-Group $GroupId))
            }
        }
        elseif ($Type -match 'groupAssignmentTarget' -or
                $Type -match 'scopeTagGroupAssignmentTarget') {

            if ($GroupId) {
                $Included.Add((Resolve-Group $GroupId))
            }
        }
        elseif ($Type -match 'allLicensedUsersAssignmentTarget|allUsersAssignmentTarget') {
            $Included.Add('All Users')
        }
        elseif ($Type -match 'allDevicesAssignmentTarget') {
            $Included.Add('All Devices')
        }
        elseif ($GroupId) {
            $Included.Add((Resolve-Group $GroupId))
        }
        else {
            $Targets.Add("Other:$Type")
        }

        $FilterId = $Target.deviceAndAppManagementAssignmentFilterId

        if ($FilterId) {
            $FilterType = $Target.deviceAndAppManagementAssignmentFilterType
            $Filters.Add("${FilterType}:$FilterId")
        }
    }

    [PSCustomObject]@{
        AssignedGroups   = ($Included | Sort-Object -Unique) -join '; '
        ExcludedGroups   = ($Excluded | Sort-Object -Unique) -join '; '
        AssignmentTarget = ($Targets | Sort-Object -Unique) -join '; '
        AssignmentFilters = ($Filters | Sort-Object -Unique) -join '; '
        AssignmentStatus = if ($script:Errors.Count -gt $BeforeErrors) {
            'Incomplete - Graph error'
        } else {
            'Retrieved'
        }
    }
}

# ------------------------------------------------------------
# PLATFORM AND SCOPE
# ------------------------------------------------------------

function Get-Platform {
    param(
        $Object,
        [string]$Default = 'Unknown'
    )

    if ($Object.platforms) {
        $Platform = [string]$Object.platforms
        return ($Platform -replace '(?i)windows10', 'Windows')
    }

    if ($Object.'@odata.type') {
        $Type = [string]$Object.'@odata.type'

        if ($Type -match 'android') { return 'Android' }
        if ($Type -match 'ios|ipad') { return 'iOS/iPadOS' }
        if ($Type -match 'macos') { return 'macOS' }
        if ($Type -match 'windows') { return 'Windows' }
    }

    return $Default
}

function Get-TextScope {
    param([string]$Text)

    if (-not $Text) { return 'Unknown' }

    $User = $Text -match '(?i)(?:^|[/_])user(?:[/_]|$)'
    $Device = $Text -match '(?i)(?:^|[/_])device(?:[/_]|$)'

    if ($User -and $Device) { return 'Mixed' }
    if ($User) { return 'User' }
    if ($Device) { return 'Device' }

    return 'Unknown'
}

function Get-ModernScope {
    param(
        [string]$Endpoint,
        [string]$Id
    )

    $Scopes = [System.Collections.Generic.List[string]]::new()
    $Evidence = [System.Collections.Generic.List[string]]::new()
    $Unresolved = 0

    $Settings = @(
        Get-GraphItems "$GraphBase/deviceManagement/$Endpoint/$Id/settings"
    )

    foreach ($Setting in $Settings) {
        $Json = $Setting | ConvertTo-Json -Depth 80

        $Matches = [regex]::Matches(
            $Json,
            '"settingDefinitionId"\s*:\s*"([^"]+)"'
        )

        foreach ($Match in $Matches) {
            $DefinitionId = $Match.Groups[1].Value

            if (-not $script:DefinitionCache.ContainsKey($DefinitionId)) {
                $Encoded = [uri]::EscapeDataString($DefinitionId)
                $Definition = Invoke-Graph (
                    "$GraphBase/deviceManagement/configurationSettings/$Encoded"
                )
                $script:DefinitionCache[$DefinitionId] = $Definition
            }

            $Definition = $script:DefinitionCache[$DefinitionId]

            $Candidates = @(
                $DefinitionId
                $Definition.cspPath
                $Definition.offsetUri
                $Definition.accessTypes
            )

            $Found = $false

            foreach ($Candidate in $Candidates) {
                $Scope = Get-TextScope ([string]$Candidate)

                if ($Scope -ne 'Unknown') {
                    $Scopes.Add($Scope)
                    $Evidence.Add([string]$Candidate)
                    $Found = $true
                }
            }

            if (-not $Found) { $Unresolved++ }
        }
    }

    $Unique = @($Scopes | Sort-Object -Unique)

    $Scope = 'Unknown'

    if ($Unique -contains 'Mixed' -or
        ($Unique -contains 'User' -and $Unique -contains 'Device')) {
        $Scope = 'Mixed'
    }
    elseif ($Unresolved -eq 0 -and $Unique.Count -gt 0) {
        $Scope = $Unique[0]
    }

    [PSCustomObject]@{
        Scope = $Scope
        Evidence = ($Evidence | Sort-Object -Unique |
            Select-Object -First 5) -join '; '
    }
}

function Get-ClassicScope {
    param($Policy)

    $Scopes = @()
    $Evidence = @()

    foreach ($Setting in @($Policy.omaSettings)) {
        if (-not $Setting) { continue }

        $Path = [string]$Setting.omaUri
        $Scope = Get-TextScope $Path

        if ($Scope -ne 'Unknown') {
            $Scopes += $Scope
            $Evidence += $Path
        }
    }

    $Unique = @($Scopes | Sort-Object -Unique)

    $Scope = 'Unknown'

    if ($Unique -contains 'Mixed' -or
        ($Unique -contains 'User' -and $Unique -contains 'Device')) {
        $Scope = 'Mixed'
    }
    elseif ($Unique.Count -eq 1) {
        $Scope = $Unique[0]
    }

    [PSCustomObject]@{
        Scope = $Scope
        Evidence = ($Evidence | Sort-Object -Unique) -join '; '
    }
}

# ------------------------------------------------------------
# CSV ROW
# ------------------------------------------------------------

function Add-Row {
    param(
        $Object,
        [string]$Type,
        [string]$Area,
        [string]$Endpoint,
        [string]$Platform,
        [string]$Scope,
        [string]$Evidence,
        [string]$ScriptRunContext = ''
    )

    $Id = Get-ValidId $Object

    if (-not $Id) {
        Write-Warning "Skipping object without valid ID."
        return
    }

    $Assignment = Get-Assignments $Area $Endpoint $Id
    
    # For scripts and remediations, determine scope from execution context
    if ($ScriptRunContext -match '^(?i:user|system)$') {
        $Scope = if ($ScriptRunContext -ieq 'user') {
            'User'
        }
        else {
            'Device'
        }
    }
    
    $Name = [string]$Object.displayName
    if (-not $Name) { $Name = [string]$Object.name }

    $script:Results.Add([PSCustomObject]@{
        Name = $Name
        Type = $Type
        Platform = $Platform
        SettingsScope = $Scope
        AssignedGroups = $Assignment.AssignedGroups
        ExcludedGroups = $Assignment.ExcludedGroups
        AssignmentFilters = $Assignment.AssignmentFilters
        AssignmentStatus = $Assignment.AssignmentStatus
        ObjectId = $Id
    })
}

# ------------------------------------------------------------
# MODERN CONFIGURATION POLICIES
# ------------------------------------------------------------

Write-Host "Reading modern configuration policies..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems "$GraphBase/deviceManagement/configurationPolicies"
)

foreach ($Policy in $Policies) {
    $Id = Get-ValidId $Policy
    if (-not $Id) { continue }

    $Scope = Get-ModernScope 'configurationPolicies' $Id

    Add-Row $Policy 'Settings Catalog / Configuration' `
        'deviceManagement' 'configurationPolicies' `
        (Get-Platform $Policy) $Scope.Scope $Scope.Evidence
}

# ------------------------------------------------------------
# CLASSIC CONFIGURATION PROFILES
# ------------------------------------------------------------

Write-Host "Reading classic configuration profiles..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems "$GraphBase/deviceManagement/deviceConfigurations"
)

foreach ($Policy in $Policies) {

    $ODataType = [string]$Policy.'@odata.type'

    if ($ODataType -match 'windowsUpdateForBusinessConfiguration') {
        $PolicyType = 'Windows Update Ring'
        $SettingsScope = 'Device'
    }
    else {
        $PolicyType = 'Classic Configuration Profile'
        $ScopeInfo = Get-ClassicScope $Policy
        $SettingsScope = $ScopeInfo.Scope
    }

    Add-Row $Policy $PolicyType `
        'deviceManagement' 'deviceConfigurations' `
        (Get-Platform $Policy) $SettingsScope ''
}

# ------------------------------------------------------------
# CLASSIC COMPLIANCE
# ------------------------------------------------------------

Write-Host "Reading classic compliance policies..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems "$GraphBase/deviceManagement/deviceCompliancePolicies"
)

foreach ($Policy in $Policies) {
    Add-Row $Policy 'Compliance Policy' `
        'deviceManagement' 'deviceCompliancePolicies' `
        (Get-Platform $Policy) 'Device' 'Device compliance evaluation'
}

# ------------------------------------------------------------
# MODERN COMPLIANCE
# ------------------------------------------------------------

Write-Host "Reading modern compliance policies..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems "$GraphBase/deviceManagement/compliancePolicies"
)

foreach ($Policy in $Policies) {
    Add-Row $Policy 'Modern Compliance Policy' `
        'deviceManagement' 'compliancePolicies' `
        (Get-Platform $Policy) 'Device' 'Device compliance evaluation'
}

# ------------------------------------------------------------
# WINDOWS SCRIPTS
# ------------------------------------------------------------

Write-Host "Reading Windows scripts..." -ForegroundColor Cyan

$Scripts = @(
    Get-GraphItems "$GraphBase/deviceManagement/deviceManagementScripts"
)

foreach ($Script in $Scripts) {
    Add-Row $Script 'Windows PowerShell Script' `
        'deviceManagement' 'deviceManagementScripts' `
        'Windows' 'Unknown' 'Script contents not analyzed' `
        ([string]$Script.runAsAccount)
}

# ------------------------------------------------------------
# REMEDIATIONS
# ------------------------------------------------------------

Write-Host "Reading Remediations..." -ForegroundColor Cyan

$Scripts = @(
    Get-GraphItems "$GraphBase/deviceManagement/deviceHealthScripts"
)

foreach ($Script in $Scripts) {
    Add-Row $Script 'Intune Remediation' `
        'deviceManagement' 'deviceHealthScripts' `
        'Windows' 'Unknown' 'Script contents not analyzed' `
        ([string]$Script.runAsAccount)
}

# ------------------------------------------------------------
# MACOS SHELL SCRIPTS
# ------------------------------------------------------------

Write-Host "Reading macOS scripts..." -ForegroundColor Cyan

$Scripts = @(
    Get-GraphItems "$GraphBase/deviceManagement/deviceShellScripts"
)

foreach ($Script in $Scripts) {
    Add-Row $Script 'macOS Shell Script' `
        'deviceManagement' 'deviceShellScripts' `
        'macOS' 'Unknown' 'Script contents not analyzed' `
        ([string]$Script.runAsAccount)
}

# ------------------------------------------------------------
# MACOS CUSTOM ATTRIBUTES
# ------------------------------------------------------------

Write-Host "Reading macOS custom attributes..." -ForegroundColor Cyan

$Scripts = @(
    Get-GraphItems (
        "$GraphBase/deviceManagement/deviceCustomAttributeShellScripts"
    )
)

foreach ($Script in $Scripts) {
    Add-Row $Script 'macOS Custom Attribute' `
        'deviceManagement' 'deviceCustomAttributeShellScripts' `
        'macOS' 'Unknown' 'Script contents not analyzed' `
        ([string]$Script.runAsAccount)
}

# ------------------------------------------------------------
# ANDROID / IOS DEVICE APP CONFIGURATION
# ------------------------------------------------------------

Write-Host "Reading mobile device app configurations..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems "$GraphBase/deviceAppManagement/mobileAppConfigurations"
)

foreach ($Policy in $Policies) {
    $Platform = Get-Platform $Policy 'Android/iOS (Unknown)'

    Add-Row $Policy 'Mobile App Configuration (Managed Device)' `
        'deviceAppManagement' 'mobileAppConfigurations' `
        $Platform 'Device' 'Managed-device app configuration'
}

# ------------------------------------------------------------
# ANDROID / IOS MAM APP CONFIGURATION
# ------------------------------------------------------------

Write-Host "Reading managed app configurations..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems (
        "$GraphBase/deviceAppManagement/targetedManagedAppConfigurations"
    )
)

foreach ($Policy in $Policies) {
    $Id = Get-ValidId $Policy
    if (-not $Id) { continue }

    $Apps = @(
        Get-GraphItems (
            "$GraphBase/deviceAppManagement/" +
            "targetedManagedAppConfigurations/$Id/apps"
        )
    )

    $Platforms = @()

    foreach ($App in $Apps) {
        $AppJson = $App | ConvertTo-Json -Depth 30

        if ($AppJson -match 'android') {
            $Platforms += 'Android'
        }
        if ($AppJson -match 'ios|ipad') {
            $Platforms += 'iOS/iPadOS'
        }
    }

    $Platform = if ($Platforms.Count -gt 0) {
        ($Platforms | Sort-Object -Unique) -join ', '
    }
    else {
        'Android/iOS (Undetermined)'
    }

    Add-Row $Policy 'Mobile App Configuration (MAM)' `
        'deviceAppManagement' 'targetedManagedAppConfigurations' `
        $Platform 'User' 'Managed-app configuration'
}

# ------------------------------------------------------------
# ANDROID APP PROTECTION
# ------------------------------------------------------------

Write-Host "Reading Android app protection..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems (
        "$GraphBase/deviceAppManagement/androidManagedAppProtections"
    )
)

foreach ($Policy in $Policies) {
    Add-Row $Policy 'App Protection Policy' `
        'deviceAppManagement' 'androidManagedAppProtections' `
        'Android' 'User' 'Mobile application management'
}

# ------------------------------------------------------------
# IOS / IPADOS APP PROTECTION
# ------------------------------------------------------------

Write-Host "Reading iOS app protection..." -ForegroundColor Cyan

$Policies = @(
    Get-GraphItems (
        "$GraphBase/deviceAppManagement/iosManagedAppProtections"
    )
)

foreach ($Policy in $Policies) {
    Add-Row $Policy 'App Protection Policy' `
        'deviceAppManagement' 'iosManagedAppProtections' `
        'iOS/iPadOS' 'User' 'Mobile application management'
}

# ------------------------------------------------------------
# EXPORT
# ------------------------------------------------------------

$Directory = Split-Path -Parent $OutputPath

if ($Directory -and -not (Test-Path $Directory)) {
    New-Item -Path $Directory -ItemType Directory -Force |
        Out-Null
}

$Sorted = @($Results | Sort-Object Platform, Type, Name)

if ($Sorted.Count -gt 0) {
    $Sorted | Export-Csv -Path $OutputPath `
        -Delimiter ';' -Encoding UTF8 -NoTypeInformation
}
else {
    Write-Warning "No objects returned. CSV not created."
}

$ErrorPath = [System.IO.Path]::ChangeExtension(
    $OutputPath, '.errors.txt'
)

if ($Errors.Count -gt 0) {
    $Errors | Set-Content -Path $ErrorPath -Encoding UTF8
}

Write-Host ""
Write-Host "Inventory completed." -ForegroundColor Green
Write-Host "Objects: $($Results.Count)"
Write-Host "Errors: $($Errors.Count)"
Write-Host "CSV: $OutputPath"

Write-Host ""
Write-Host "Platform distribution:"

$Results |
    Group-Object Platform |
    Sort-Object Name |
    ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }

Write-Host ""
Write-Host "Scope distribution:"

$Results |
    Group-Object SettingsScope |
    Sort-Object Name |
    ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)"
    }
