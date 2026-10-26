
# Detect duplicate desktop shortcuts
# Supports Swedish, English, Danish, Norwegian, Finnish, German
# Exit 0 = Compliant
# Exit 1 = Duplicates found or detection error

$ErrorActionPreference = 'Stop'

$CopyPattern = '\s+-\s+(?:kopia|copy|kopi|kopio|kopie)(?:\s+\(\d+\))?$'

function Get-OriginalName {
    param([string]$BaseName)

    $Name = $BaseName

    # Handle repeated copy suffixes
    while ($Name -match $CopyPattern) {
        $Name = $Name -replace $CopyPattern, ''
    }

    return $Name
}

try {
    $DesktopPaths = @(
        [Environment]::GetFolderPath('DesktopDirectory')
        [Environment]::GetFolderPath('CommonDesktopDirectory')
    ) | Where-Object {
        $_ -and (Test-Path -LiteralPath $_ -PathType Container)
    } | Select-Object -Unique

    $Duplicates = @()

    foreach ($DesktopPath in $DesktopPaths) {
        $Shortcuts = @(
            Get-ChildItem -LiteralPath $DesktopPath -File |
                Where-Object { $_.Extension -in '.lnk', '.url' }
        )

        foreach ($Shortcut in $Shortcuts) {
            $OriginalBaseName = Get-OriginalName $Shortcut.BaseName

            if ($OriginalBaseName -ceq $Shortcut.BaseName) {
                continue
            }

            $OriginalPath = Join-Path $DesktopPath (
                $OriginalBaseName + $Shortcut.Extension
            )

            if (Test-Path -LiteralPath $OriginalPath -PathType Leaf) {
                $Duplicates += $Shortcut.FullName
            }
        }
    }

    if ($Duplicates.Count -gt 0) {
        Write-Output "Found $($Duplicates.Count) duplicate shortcut(s):"
        $Duplicates | ForEach-Object { Write-Output $_ }
        exit 1
    }

    Write-Output "Compliant: No duplicate shortcuts found."
    exit 0
}
catch {
    Write-Output "Detection error: $($_.Exception.Message)"
    exit 1
}
