<#
.SYNOPSIS
    Collect Windows Autopilot hardware hash and device inventory, then upload
    one hash CSV and one inventory CSV per device to Azure Blob Storage.

.DESCRIPTION
    Designed for a Group Policy computer startup script running as SYSTEM.
    Every device running the script can upload if it has the SAS token.

    Files are placed directly in the root of ONE EXISTING blob container:
        <SerialNumber>-Hash.csv
        <SerialNumber>-Inventory.csv

    No Azure modules or interactive Azure sign-in are required. Azure Blob
    Storage DOES require upload authorization: configure a short-lived,
    container-scoped SAS granting only Create (c), HTTPS only. The SAS is a
    bearer credential: any holder can create blobs during its validity.

    Local files and logs remain in C:\ProgramData\AutopilotCollection.
    Successful devices are marked complete to avoid repeated uploads.
#>

# -------------------------------------------------------------------
# CONFIGURATION - EDIT THESE TWO SETTINGS
# -------------------------------------------------------------------

# Existing storage account and container; NO trailing slash, NO folder path.
$BlobContainerUrl = 'https://[blobstorage].blob.core.windows.net/files'

# SAS for the CONTAINER, not the storage account key. Give it only:
#   Create (c) permission, HTTPS, and a short validity window.
# Do not include a leading '?' (the script tolerates one if provided).
$SasToken = '[SASTOKEN]'

# -------------------------------------------------------------------
# Local logging / staging (no folders are created in Azure)
# -------------------------------------------------------------------

$LocalFolder = Join-Path $env:ProgramData 'AutopilotCollection'
$LocalLogFile = Join-Path $LocalFolder 'AutopilotCollection.log'

try {
    New-Item -Path $LocalFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
}
catch {
    exit 1
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')][string]$Level = 'INFO'
    )
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    try {
        Add-Content -LiteralPath $LocalLogFile -Value "$Timestamp [$Level] $Message" -Encoding UTF8 -ErrorAction Stop
    }
    catch { }
}

Write-Log 'Starting Autopilot collection for Azure Blob Storage.'

# -------------------------------------------------------------------
# Read the serial number for CSV contents and blob filenames.
# -------------------------------------------------------------------

try {
    $BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $SerialNumber = ([string]$BIOS.SerialNumber).Trim()
    if ([string]::IsNullOrWhiteSpace($SerialNumber)) {
        throw 'The BIOS serial number is missing.'
    }
}
catch {
    Write-Log "Could not read BIOS serial number: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# Blob names cannot contain directory separators. Replace unsafe characters
# to produce a safe filename while preserving the real serial in the CSV.
$SafeSerial = $SerialNumber -replace '[^A-Za-z0-9._-]', '_'
if ([string]::IsNullOrWhiteSpace($SafeSerial) -or $SafeSerial -eq '.' -or $SafeSerial -eq '..') {
    Write-Log "Serial '$SerialNumber' cannot be turned into a safe filename." 'ERROR'
    exit 1
}

$CompleteFile = Join-Path $LocalFolder "$SafeSerial.UploadComplete"
$HashDoneFile = Join-Path $LocalFolder "$SafeSerial.HashUploaded"
$InventoryDoneFile = Join-Path $LocalFolder "$SafeSerial.InventoryUploaded"
if (Test-Path -LiteralPath $CompleteFile) {
    Write-Log "Serial '$SerialNumber' was already uploaded successfully. Skipping."
    exit 0
}

if ($BlobContainerUrl -notmatch '^https://[a-zA-Z0-9-]+\.blob\.core\.windows\.net/[a-z0-9-]+/?$' -or
    $BlobContainerUrl -match 'YOURSTORAGEACCOUNT' -or
    $SasToken -eq 'PASTE_CONTAINER_CREATE_ONLY_SAS_HERE') {
    Write-Log 'Blob storage URL or SAS token has not been configured.' 'ERROR'
    exit 1
}

$SasToken = $SasToken.Trim().TrimStart('?')
# Refuse an overly permissive SAS; only Create (c) is needed.
$PermissionMatch = [regex]::Match($SasToken, '(?:^|&)sp=([^&]+)')
$SasPermissions = [Uri]::UnescapeDataString($PermissionMatch.Groups[1].Value)
if ($SasPermissions -ne 'c') {
    Write-Log 'SAS must have exactly Create (c) permission; no read/write/list/delete.' 'ERROR'
    exit 1
}

# -------------------------------------------------------------------
# Gather the original inventory fields.
# -------------------------------------------------------------------

try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $OS             = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    $ComputerName = $env:COMPUTERNAME
    $Manufacturer = ([string]$ComputerSystem.Manufacturer).Trim()
    $Model        = ([string]$ComputerSystem.Model).Trim()
    $LoggedOnUser = [string]$ComputerSystem.UserName

    Write-Log "Device: $ComputerName, serial: $SerialNumber, model: $Manufacturer $Model"
}
catch {
    Write-Log "Unable to collect device inventory: $($_.Exception.Message)" 'ERROR'
    exit 1
}

$ProductID = ''
try {
    $ProductID = [string](Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
        -Name ProductId -ErrorAction Stop).ProductId
}
catch {
    Write-Log 'Windows Product ID could not be retrieved; leaving the field empty.' 'WARNING'
}

# -------------------------------------------------------------------
# Windows Autopilot hardware hash (same CIM method as the original).
# -------------------------------------------------------------------

try {
    $DevDetail = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
        -ClassName 'MDM_DevDetail_Ext01' `
        -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
        -ErrorAction Stop
    $HardwareHash = [string]$DevDetail.DeviceHardwareData
    if ([string]::IsNullOrWhiteSpace($HardwareHash)) {
        throw 'DeviceHardwareData is empty.'
    }
    Write-Log 'Successfully retrieved the Autopilot hardware hash.'
}
catch {
    Write-Log "Unable to retrieve Autopilot hardware hash: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# -------------------------------------------------------------------
# Create exactly two CSVs, named with serial number FIRST.
# -------------------------------------------------------------------

$HashName      = "$SafeSerial-Hash.csv"
$InventoryName = "$SafeSerial-Inventory.csv"
$HashFile      = Join-Path $LocalFolder $HashName
$InventoryFile = Join-Path $LocalFolder $InventoryName

$HashData = [PSCustomObject][ordered]@{
    'Device Serial Number' = $SerialNumber
    'Windows Product ID'   = $ProductID
    'Hardware Hash'        = $HardwareHash
    'Group Tag'            = 'Denmark'
}

$InventoryData = [PSCustomObject][ordered]@{
    ComputerName   = $ComputerName
    SerialNumber   = $SerialNumber
    Manufacturer   = $Manufacturer
    Model          = $Model
    ProductID      = $ProductID
    LoggedOnUser   = $LoggedOnUser
    WindowsVersion = [string]$OS.Caption
    OSBuild        = [string]$OS.BuildNumber
    Collected      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

try {
    # ASCII works for the four Autopilot fields and matches the original.
    $HashData | Export-Csv -LiteralPath $HashFile -NoTypeInformation -Encoding ASCII -Force -ErrorAction Stop
    $InventoryData | Export-Csv -LiteralPath $InventoryFile -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop
    Write-Log "Created $HashName and $InventoryName locally."
}
catch {
    Write-Log "Unable to generate CSV files: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# -------------------------------------------------------------------
# Upload directly to the container root using Azure Blob REST API.
# The create-only SAS + If-None-Match prevents overwriting existing blobs.
# -------------------------------------------------------------------

function Send-BlobCsv {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$BlobName
    )

    $EncodedName = [Uri]::EscapeDataString($BlobName)
    $Uri = '{0}/{1}?{2}' -f $BlobContainerUrl.TrimEnd('/'), $EncodedName, $SasToken
    $Headers = @{
        'x-ms-blob-type' = 'BlockBlob'
        'x-ms-version'   = '2021-12-02'
        'If-None-Match'  = '*'
    }

    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        try {
            $Headers['x-ms-date'] = [DateTime]::UtcNow.ToString('R', [Globalization.CultureInfo]::InvariantCulture)
            Invoke-WebRequest -Uri $Uri -Method Put -InFile $FilePath `
                -ContentType 'text/csv; charset=utf-8' -Headers $Headers `
                -UseBasicParsing -ErrorAction Stop | Out-Null
            Write-Log "Uploaded $BlobName to the root of the blob container."
            return $true
        }
        catch {
            $StatusCode = 0
            try {
                if ($null -ne $_.Exception.Response) {
                    $StatusCode = [int]$_.Exception.Response.StatusCode
                }
            }
            catch { }

            # A prior upload can already exist after an interrupted run.
            # It is NOT overwritten. Existing content isn't verified here.
            $AzureErrorCode = ''
            try {
                $AzureErrorCode = [string]$_.Exception.Response.Headers['x-ms-error-code']
            }
            catch { }
            if ($StatusCode -eq 412 -or
                ($StatusCode -eq 409 -and $AzureErrorCode -eq 'BlobAlreadyExists')) {
                Write-Log "$BlobName already exists in Blob Storage; not overwritten. Verify its contents if unexpected." 'WARNING'
                return $true
            }

            Write-Log "Upload failed for $BlobName (attempt $Attempt/3; HTTP $StatusCode): $($_.Exception.Message)" 'WARNING'

            $Transient = ($StatusCode -eq 0 -or $StatusCode -eq 408 -or
                          $StatusCode -eq 429 -or $StatusCode -ge 500)
            if (-not $Transient -or $Attempt -eq 3) {
                return $false
            }
            Start-Sleep -Seconds (2 * $Attempt)
        }
    }
    return $false
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Log "Could not enable TLS 1.2: $($_.Exception.Message)" 'ERROR'
    exit 1
}

# Per-file success stamps help recover if only one of the two uploads succeeds.
$HashUploaded = $false
$InventoryUploaded = $false

if (Test-Path -LiteralPath $HashDoneFile) {
    Write-Log "$HashName was previously uploaded; skipping this file."
    $HashUploaded = $true
}
else {
    $HashUploaded = Send-BlobCsv -FilePath $HashFile -BlobName $HashName
    if ($HashUploaded) {
        try { Set-Content -LiteralPath $HashDoneFile -Value (Get-Date -Format 'o') -Encoding ASCII -ErrorAction Stop }
        catch { Write-Log "Could not write success stamp for $HashName." 'WARNING' }
    }
}

if (Test-Path -LiteralPath $InventoryDoneFile) {
    Write-Log "$InventoryName was previously uploaded; skipping this file."
    $InventoryUploaded = $true
}
else {
    $InventoryUploaded = Send-BlobCsv -FilePath $InventoryFile -BlobName $InventoryName
    if ($InventoryUploaded) {
        try { Set-Content -LiteralPath $InventoryDoneFile -Value (Get-Date -Format 'o') -Encoding ASCII -ErrorAction Stop }
        catch { Write-Log "Could not write success stamp for $InventoryName." 'WARNING' }
    }
}

if (-not ($HashUploaded -and $InventoryUploaded)) {
    Write-Log 'One or both uploads failed. Local CSVs were retained for troubleshooting and retry.' 'ERROR'
    exit 1
}

try {
    Set-Content -LiteralPath $CompleteFile -Value (Get-Date -Format 'o') -Encoding ASCII -ErrorAction Stop
}
catch {
    Write-Log "Both files uploaded, but could not record local completion: $($_.Exception.Message)" 'WARNING'
}

Write-Log "Collection completed successfully for $SerialNumber."
exit 0
