# PowerShell Scripts

PowerShell tools for **Microsoft Intune, Microsoft Entra ID, Windows Autopilot, endpoint administration, application deployment, and troubleshooting**.

This repository is a collection of standalone administrative scripts rather than a single module or packaged product. Some scripts are read-only reporting tools; others change device settings, remove shortcuts, or uninstall applications. Each script should be reviewed and tested in a lab before deployment.

**Repository:** [Gandolof/PowerShell](https://github.com/Gandolof/PowerShell)  
**Maintainer:** [Gandolof](https://github.com/Gandolof)

## Script catalog

### Intune inventory and assignments

| Script | Purpose |
| --- | --- |
| [Export-IntuneDeviceInventory.ps1](./Export-IntuneDeviceInventory.ps1) | Export an Intune-managed device inventory across Windows, macOS, iOS/iPadOS, and Android, including platform-specific details. |
| [Export-IntuneWindowsInventory.ps1](./Export-IntuneWindowsInventory.ps1) | Export Windows device data enriched with Windows Autopilot, Windows 11 readiness, and health-attestation information where available. |
| [Export-IntunePolicyInventory.ps1](./Export-IntunePolicyInventory.ps1) | Inventory Intune configuration, compliance, scripts, remediations, app configuration, and app protection policies with assignment information. |
| [Application-Inventory.ps1](./Application-Inventory.ps1) | Export a consolidated inventory of discovered applications from Intune, including application names, versions, publishers, platforms, and unique device counts. |
| [Intune-GroupAssignments-GUI.ps1](./Intune-GroupAssignments-GUI.ps1) | Search for Intune policies and applications directly assigned to an Entra group or the built-in **All Users** / **All Devices** targets. |
| [AddUsersWithAppInstallFailuresToGroup.ps1](./AddUsersWithAppInstallFailuresToGroup.ps1) | Find users with failed Intune app installations and add eligible users to a specified Entra group, with a configurable limit. |

### Autopilot and device provisioning

| Script | Purpose |
| --- | --- |
| [Get-WindowsAutopilotInfoGP.ps1](./Get-WindowsAutopilotInfoGP.ps1) | Collect Windows Autopilot hardware hashes and device inventory centrally through a Group Policy computer startup script. |
| [Get-WindowsAutopilotInfo-Blob.ps1](#collect-autopilot-hardware-hashes-using-azure-blob-storage) | Collect Autopilot hardware hashes and device inventory to Azure Blob Storage using a create-only SAS token and a Group Policy startup script. |
| [Set-AutopilotLanguage.ps1](./Set-AutopilotLanguage.ps1) | Apply supported Nordic language, region, and time-zone settings based on Windows Autopilot policy data. |

### Endpoint cleanup and remediation

| Script | Purpose |
| --- | --- |
| [RemoveDuplicateShortcuts-Detect.ps1](./RemoveDuplicateShortcuts-Detect.ps1) | Detect desktop `.lnk` and `.url` shortcuts with recognized multilingual copy suffixes. |
| [RemoveDuplicateShortcuts-Remediate.ps1](./RemoveDuplicateShortcuts-Remediate.ps1) | Delete recognized duplicate shortcuts only when the corresponding original exists; write a local log. |
| [M365AppsUpdateBlockers-Detect.ps1](./M365AppsUpdateBlockers-Detect.ps1) | Detect Microsoft 365 Apps Click-to-Run update failures caused by running applications that veto shutdown. |
| [M365AppsUpdateBlockers-Remediate.ps1](./M365AppsUpdateBlockers-Remediate.ps1) | Guide users through closing applications blocking Microsoft 365 Apps servicing, with document-safety checks and local logging. |
| [XCS-RemoveUnwantedApps-Detect.ps1](./XCS-RemoveUnwantedApps-Detect.ps1) | Check a configured list of unwanted AppX, provisioned, Win32, and WinGet applications. |
| [XCS-RemoveUnwantedApps-Remediate.ps1](./XCS-RemoveUnwantedApps-Remediate.ps1) | Framework for uninstalling specified applications using available removal methods. |

### Diagnostics and application execution

| Script | Purpose |
| --- | --- |
| [GatherEventLogEvents.ps1](./GatherEventLogEvents.ps1) | Collect relevant WDAC / Code Integrity and AppLocker audit events for investigation. |

## Script details

### Intune device inventory (all platforms)

**File:** [Export-IntuneDeviceInventory.ps1](./Export-IntuneDeviceInventory.ps1)

Exports managed devices for Windows, macOS, iOS/iPadOS, and Android. Fields include device identity, OS and hardware information, management data, and platform-specific information where exposed by Microsoft Graph. Windows records may be enriched with Autopilot and reporting data.

```powershell
.\Export-IntuneDeviceInventory.ps1 -OutputPath '.\Intune-Devices.csv'
```

Optional parameters: `-TenantId` (select a tenant) and `-SkipPerDeviceDetails` (skip additional per-device queries). The default output is a timestamped CSV in the current directory. **Read-only.**

### Intune Windows device inventory

**File:** [Export-IntuneWindowsInventory.ps1](./Export-IntuneWindowsInventory.ps1)

Produces a Windows-focused device inventory, with Autopilot registration information, Windows 11 readiness information, and device health / Secure Boot attestation data **where available**.

```powershell
.\Export-IntuneWindowsInventory.ps1 -OutputPath '.\Intune-Windows.csv'
```

Supports `-TenantId` and `-SkipPerDeviceDetails`. The default output is a timestamped CSV in the current directory. **Missing report data should be treated as unknown, not as evidence that a feature is disabled. Read-only.**

### Intune policy and script inventory

**File:** [Export-IntunePolicyInventory.ps1](./Export-IntunePolicyInventory.ps1)

Exports settings catalog / modern configuration policies, classic configuration and compliance policies, PowerShell scripts, remediations, macOS scripts and custom attributes, and supported mobile app configuration and protection policies.

The CSV includes fields such as `Name`, `Type`, `Platform`, `SettingsScope`, `AssignedGroups`, `ExcludedGroups`, `AssignmentFilters`, `AssignmentStatus`, and `ObjectId`. Assignment and execution scope are represented separately. The CSV uses a **semicolon (`;`) delimiter**.

```powershell
.\Export-IntunePolicyInventory.ps1 -OutputPath '.\Intune-Policies.csv'
```

The default destination is `Intune-Inventory.csv` next to the script. Graph endpoint failures are reported as warnings; if errors were collected, a corresponding `.errors.txt` file is created. Uses Microsoft Graph beta endpoints. **Read-only.**

### Application inventory

**File:** [Application-Inventory.ps1](./Application-Inventory.ps1)

Exports a consolidated inventory of **discovered applications** from Microsoft Intune using Microsoft Graph. Groups applications by name and platform, combines detected versions, and counts unique devices to prevent duplicate installations from inflating totals.

Features include:

- Application name, version, publisher, platform, and device count.
- Consolidation of multiple application versions into a single entry.
- Unique device counts across application versions.
- Automatic polling of Microsoft Graph export jobs.
- UTF-8 CSV export using semicolon delimiters.

```powershell
.\Application-Inventory.ps1 -OutputPath "C:\Reports\Application-Inventory.csv"
```

Requires `Microsoft.Graph.Authentication` and the Graph permission `DeviceManagementApps.ReadWrite.All`. Uses the Graph beta reporting endpoint (`AppInvRawData`). Default output is `DiscoveredApps-Grouped.csv` in the script directory. **Read-only.**

### Intune group assignment explorer

**File:** [Intune-GroupAssignments-GUI.ps1](./Intune-GroupAssignments-GUI.ps1)

The answer to the question "what is this group for?". Windows/WPF application to inspect **direct assignments** of Intune configurations, apps, scripts, remediations, and related workloads. Search by an Entra group's exact display name or GUID, or type **`All Users`** or **`All Devices`** to search those built-in Intune assignment targets.

Features include:

- Included/excluded assignments, assignment intent, platform/type, and assignment filter display.
- Filter names resolved from Graph when accessible.
- A **Retain results** checkbox for combining several searches.
- On-screen filtering and CSV export of collected results.

```powershell
powershell.exe -NoProfile -STA -File '.\Intune-GroupAssignments-GUI.ps1'
```

Requires Windows, WPF, and `Microsoft.Graph.Authentication`. This is **not** an effective-policy calculator: it does not resolve nested groups or all user/device membership and filter outcomes. Uses Graph beta endpoints. **Read-only.**

### Add users with Intune app installation failures to an Entra group

**File:** [AddUsersWithAppInstallFailuresToGroup.ps1](./AddUsersWithAppInstallFailuresToGroup.ps1)

Identifies users with **failed installations of a specified Intune application** and adds eligible users to an Entra group. Uses the Microsoft Graph beta `getUserInstallStatusReport` endpoint and skips accounts that are already direct members of the target group.

Features include:

- Retrieves and pages through per-user installation failure results for a selected application.
- Filters for users with a `FailedCount` greater than zero and removes duplicate results.
- Checks existing group membership to avoid adding the same user twice.
- Limits the number of **new** members added while still listing users skipped due to the limit.
- Prints counts for failures, existing members, eligible users, successful additions, and skipped users.

**Before running:** set `$AppId` and `$GroupId` in the script. `$MaxUsersToAdd` defaults to `5`; set it to `0` to process all eligible users.

```powershell
.\AddUsersWithAppInstallFailuresToGroup.ps1
```

Requires Microsoft Graph PowerShell authentication, group, and user cmdlets, with delegated permissions `DeviceManagementApps.Read.All`, `User.Read.All`, and `GroupMember.ReadWrite.All`. The script connects to Graph interactively and **modifies Entra group membership**. Uses a Graph beta report; review the target application, group, and addition limit before execution.

### Collect Autopilot hardware hashes using Group Policy

**File:** [Get-WindowsAutopilotInfoGP.ps1](./Get-WindowsAutopilotInfoGP.ps1)

Designed for use as an **Active Directory computer startup script**. Collects Autopilot hardware-hash information, serial number, make/model, computer name, product ID, user information, and timestamp. Writes a device-specific Autopilot CSV and a separate inventory CSV to a central SMB share.

**Before deployment:** replace the placeholder `$CentralShare = "\\SERVER\AutopilotCollection$"` in the script and ensure computer accounts have suitable access to the share and its destination folders.

Local log: `C:\ProgramData\AutopilotCollection\AutopilotCollection.log`.

<a id="collect-autopilot-hardware-hashes-using-azure-blob-storage"></a>

### Collect Autopilot hardware hashes using Azure Blob Storage

**File:** [Get-WindowsAutopilotInfo-Blob.ps1](./Get-WindowsAutopilotInfo-Blob.ps1)

Designed as an **Active Directory Group Policy computer startup script** running as **SYSTEM**. Collects the Windows Autopilot hardware hash and device information, then uploads two serial-number-based CSV files directly to an existing Azure Blob Storage container using HTTPS and a **create-only SAS token**. No Azure PowerShell modules or interactive sign-in are required.

Features include:

- `<SerialNumber>-Hash.csv` containing serial number, Windows Product ID, hardware hash, and a **Group Tag** currently fixed to `Denmark`.
- `<SerialNumber>-Inventory.csv` containing computer name, serial number, manufacturer, model, Windows version/build, logged-on user, and collection time.
- An Azure Blob REST API upload with a SAS restricted to **Create (`c`) only**; existing blobs are never overwritten.
- Retry handling for transient upload failures and local completion markers to avoid repeated successful uploads.
- Local CSV files and troubleshooting logs retained under `C:\ProgramData\AutopilotCollection\`.

**Before deployment:** configure `$BlobContainerUrl` and `$SasToken` in the script. Use an **existing blob container** and a short-lived, **container-scoped, HTTPS-only SAS** with exactly `Create (c)` permission (no read, write, list, or delete). Ensure endpoints can reach Azure Blob Storage over HTTPS, and protect the SAS as a bearer credential.

```powershell
.\Get-WindowsAutopilotInfo-Blob.ps1
```

Log file: `C:\ProgramData\AutopilotCollection\AutopilotCollection.log`. Successful uploads are marked locally and skipped on subsequent runs. **Note:** when a blob already exists, the script does not verify its contents; it treats the existing blob as uploaded successfully.

### Set Windows Autopilot language and time zone

**File:** [Set-AutopilotLanguage.ps1](./Set-AutopilotLanguage.ps1)

Configures **Danish (`da-DK`), Finnish (`fi-FI`), Norwegian Bokmål (`nb-NO`), or Swedish (`sv-SE`)** language and regional settings based on Autopilot profile/cache information. Honors `os-default` by leaving Windows language settings unchanged. Designed to run from an **Intune Win32 app in 64-bit SYSTEM context**.

For Windows 11 **25H2 / build 26200**, the script expects required matching language CABs in a sibling `Languages\` folder within the Win32 app package. That folder and its CAB files are **not included in this repository**. Other builds follow the script's `Install-Language` path. Review and validate OS-build behavior before rollout.

Local log: `C:\ProgramData\COMPANY\Logs\AutopilotLanguage.log`.  
Registry status: `HKLM\SOFTWARE\COMPANY`, including `LanguageConfigurationStatus` and `LanguageConfigurationProcessed`.

**Customization:** replace the `COMPANY` placeholders to suit your organization. An incomplete installation returns a nonzero exit code so Intune can retry; do not make it an ESP-blocking required app unless the end-to-end behavior has been validated.

### Remove duplicate desktop shortcuts

**Files:** [Detection](./RemoveDuplicateShortcuts-Detect.ps1) · [Remediation](./RemoveDuplicateShortcuts-Remediate.ps1)

Designed as an **Intune Remediations** pair. Checks the executing user's desktop and the public desktop for duplicate `.lnk` / `.url` files, using language-specific copy suffixes. Remediation removes a matching duplicate **only if its original shortcut is present**.

The remediation also recognizes plain numeric suffixes, such as `Application (1).lnk`, while the **current detection script does not**. Align the two patterns before depending on numeric-only names to trigger automatic remediation.

The remediation logs to:

```text
%LOCALAPPDATA%\COMPANY\DuplicateDesktopShortcuts.log
```

Replace the `COMPANY` placeholder as appropriate. For user-desktop cleanup, deploy in the **logged-on user's context**; changes to the public desktop may require additional permissions. Detection uses exit code `1` for detected duplicates or errors and `0` when compliant.

### Resolve Microsoft 365 Apps update blockers

**Files:** [Detection](./M365AppsUpdateBlockers-Detect.ps1) · [Remediation](./M365AppsUpdateBlockers-Remediate.ps1)

An **Intune Remediations** pair for Microsoft 365 Apps Click-to-Run servicing that is blocked by open applications. The detection script examines the **five newest** user-context Click-to-Run log files in `%TEMP%` and evaluates the latest `Office.ClickToRun.ProcessKillerShutdown` event for a specific application-veto failure signature.

Features include:

- Detection returns exit code `1` for a matching blocker event and `0` otherwise.
- An interactive **WPF dialog** guides the user through closing applications so servicing can continue.
- On the first proceed, the remediation automatically closes selected communication applications and attempts to close Office applications through COM, checking saved state and AutoSave where available.
- Applications with unconfirmed unsaved work are left open during the initial pass; a subsequent user-approved attempt requests normal window closure (`WM_CLOSE`) for remaining protected Office applications.
- Detection and remediation write local troubleshooting information to the same log file.

The scripts are designed to run in the **logged-on user's context** on Windows, with an interactive desktop available for the remediation dialog. This is not a silent SYSTEM-context cleanup and can close running applications; users should save their work before proceeding.

Log file:

```text
%LOCALAPPDATA%\COMPANY\M365AppsUpdateRemediation.log
```

Replace the `COMPANY` placeholder in **both** scripts. Detection deliberately matches a narrow Click-to-Run log signature and may not identify every Office update failure. Review the application-close behavior and test with saved, unsaved, and AutoSave-enabled documents before production deployment.

### Remove unwanted applications (deprecated, containing legacy examples)

**Files:** [Detection](./XCS-RemoveUnwantedApps-Detect.ps1) · [Remediation](./XCS-RemoveUnwantedApps-Remediate.ps1)

An older Intune Remediations-style solution that examines WinGet, AppX/AppX-provisioned, and Win32 application entries and includes uninstall routines. The scripts rely on editable `$appNames` arrays and may require WinGet availability and elevated permissions.

**These files must not be deployed as an unchanged detection/remediation pair.** In the current repository version:

- The detection script uses two different variables (`$foundApps` and `$appsFound`) for the final compliance decision; its exit code can therefore be incorrect.
- The remediation script's application entries are all commented out, while the detection script's list is populated (and includes apps such as Photos, Teams, Firefox, and OneDrive).

Select and review the desired applications, align the lists, correct the detection logic, and test removal and rollback implications before use.

### Gather WDAC and AppLocker audit events

**File:** [GatherEventLogEvents.ps1](./GatherEventLogEvents.ps1)

Collects and parses recent events from `Microsoft-Windows-CodeIntegrity/Operational` and `Microsoft-Windows-AppLocker/MSI and Script`, useful when investigating **Windows Defender Application Control (WDAC)** audit activity. The script is configured to inspect up to 500 events per relevant log.

```powershell
.\GatherEventLogEvents.ps1
```

Writes a timestamped CSV, execution log, and error log under:

```text
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\
```

Ensure the executing account can read the event channels and write to this directory. The script does not change WDAC policy.

## Disclaimer

These scripts are provided **as-is**, with no guarantee of fitness for any environment. **Review, test, and validate them before production use.** Some can modify operating-system settings, remove files, or uninstall software. You are responsible for permissions, backups, change control, and deployment outcomes.

For problems or suggestions, [open an issue](https://github.com/Gandolof/PowerShell/issues).
