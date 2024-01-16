# =================================================================== #
#  *-*-*   +   -   *   +   -*-*   +   -   *   +   -*-*   +   -   *    #
#  +   *   -   +   *   -   +   *   -   +   *   -   +   *   -   +   *  #
#  -*-*   +   -   *   +   -*-*   +   -   *   +   -*-*   +   -   *     #
#  +   *   -   +   *   -   +   *   -   +   *   -   +   *   -   +   *  #
#  *-*-*   +   -   *   +   -*-*   +   -   *   +   -*-*   +   -   *    #
# =================================================================== #
#                   Created by Azrael (LukeHjo)                       #
#                           22/12/2023                                #
# =================================================================== #

#----------------------------------------------
# Script Imports
#----------------------------------------------

Import-Module Microsoft.PowerShell.Security
Import-Module Microsoft.PowerShell.Management

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NativeMethods {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr MessageBox(IntPtr hWnd, String text, String caption, uint type);
}
"@

#----------------------------------------------
# Script Functions
#----------------------------------------------

function Log-Message {
    param (
        [string]$Message
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage
}

TRAP {
    Log-Message $_.Exception.Message
    continue
}

#----------------------------------------------
# Script Information
#----------------------------------------------

$scriptInfo = [PSCustomObject]@{
    "Script Name"        = "GenerateSystemReport (GSR)"
    "Script Version"     = "1.0.2"
    "Script Description" = "A lightweight script that generates a system report for troubleshooting purposes."
    "Script Author"      = "Azrael (LukeHjo)"
    "Script Date"        = "22/12/2023"
    "Script License"     = "MIT"
    "Script Repository"  = "https://github.com/luke-beep/GSR"
}

#----------------------------------------------
# Print Script Information
#----------------------------------------------

# Display the script information
$scriptInfo | Format-List

#----------------------------------------------
# Script Variables
#----------------------------------------------

# System Drive
$systemDrive = $env:SystemDrive

# Empty Folder
$emptyFolder = "$systemDrive\Empty"

# System Reports Folder
$systemReportsFolder = "$systemDrive\SystemReports"

# Custom Folder
$customFolder = ""

# Use Custom Folder
$useCustomFolder = $false

# Report Folder
if ($useCustomFolder -eq $true) {
    $reportFolder = $customFolder
}
else {
    $reportFolder = $systemReportsFolder
}

# Debug Folder
$debugFolder = "$reportFolder\Debug"

# Debug Mode
$debug = $false

# Transcript File
$transcriptFile = "$reportFolder\debug.txt"

$scriptVariables = [PSCustomObject]@{
    "System Drive"          = $systemDrive
    "Empty Folder"          = $emptyFolder
    "System Reports Folder" = $systemReportsFolder
    "Custom Folder"         = $customFolder
    "Use Custom Folder"     = $useCustomFolder
    "Report Folder"         = $reportFolder
    "Debug Folder"          = $debugFolder
    "Debug Mode"            = $debug
    "Transcript File"       = $transcriptFile
}

#----------------------------------------------
# Print Script Variables
#----------------------------------------------

# Display the script variables
$scriptVariables | Format-List

#----------------------------------------------
# Script Execution
#----------------------------------------------

try {
    # Local Variables
    $hardwareInformationFolder = "$reportFolder\HardwareInformation"
    $operatingSystemDetailsFolder = "$reportFolder\OperatingSystemDetails"
    $networkConfigurationDiagnosticsFolder = "$reportFolder\NetworkConfigurationDiagnostics"
    $diskStorageInformationFolder = "$reportFolder\DiskStorageInformation"
    $systemSecurityAuditFolder = "$reportFolder\SystemSecurityAudit"
    $systemApplicationLogsFolder = "$reportFolder\SystemApplicationLogs"
    $servicesProcessesFolder = "$reportFolder\ServicesProcesses"
    $installedSoftwareDriversFolder = "$reportFolder\InstalledSoftwareDrivers"
    $systemPerformanceDiagnosticsFolder = "$reportFolder\SystemPerformanceDiagnostics"
    $advancedSystemInformationFolder = "$reportFolder\AdvancedSystemInformation"
    $powerManagementFolder = "$reportFolder\PowerManagement"
    $userGroupInformationFolder = "$reportFolder\UserGroupInformation"
    $backupRestoreInformationFolder = "$reportFolder\BackupRestoreInformation"

    $logFolderCreated = $false
    $logFolderRecreated = $false
    $transcriptCreated = $false
    $transcriptRecreated = $false
    $emptyFolderCreated = $false
    $emptyFolderRecreated = $false
    
    # Create Report Folder
    if (!(Test-Path $reportFolder)) {
        New-Item -ItemType Directory -Path $reportFolder
        $logFolderCreated = $true
    }
    else {
        Start-Process robocopy -ArgumentList "/mir $emptyFolder $reportFolder" -NoNewWindow -Wait
        Remove-Item -Recurse -Force $reportFolder
        $logFolderRecreated = $true
    }

    # Create Transcript File
    if (!(Test-Path $transcriptFile)) {
        New-Item -ItemType File -Path $transcriptFile
        $transcriptCreated = $true
    }
    else {
        Remove-Item -Force $transcriptFile
        New-Item -ItemType File -Path $transcriptFile
        $transcriptRecreated = $true
    }

    # Create Empty Folder
    if (!(Test-Path $emptyFolder)) {
        New-Item -ItemType Directory -Path $emptyFolder
        $emptyFolderCreated = $true
    }
    else {
        Remove-Item -Recurse -Force $emptyFolder
        New-Item -ItemType Directory -Path $emptyFolder
        $emptyFolderRecreated = $true
    }

    # Create README File
    $scriptInfo | Out-File "$reportFolder\README.txt"
    $scriptVariables | Out-File "$reportFolder\README.txt" -Append

    # Start Transcript
    Start-Transcript -Path $transcriptFile -Append

    if ($debug -eq $true) {
        Log-Message "Debug mode enabled"
        # Create Debug Folder
        New-Item -ItemType Directory -Path $debugFolder
        Log-Message "Created Debug Folder: $debugFolder"

        # Start Debugging

        # Stop Transcript
        Stop-Transcript
    }
    else {
        # Create Folders
        New-Item -ItemType Directory -Path $hardwareInformationFolder
        New-Item -ItemType Directory -Path $operatingSystemDetailsFolder
        New-Item -ItemType Directory -Path $networkConfigurationDiagnosticsFolder
        New-Item -ItemType Directory -Path $diskStorageInformationFolder
        New-Item -ItemType Directory -Path $systemSecurityAuditFolder
        New-Item -ItemType Directory -Path $systemApplicationLogsFolder
        New-Item -ItemType Directory -Path $servicesProcessesFolder
        New-Item -ItemType Directory -Path $installedSoftwareDriversFolder
        New-Item -ItemType Directory -Path $systemPerformanceDiagnosticsFolder
        New-Item -ItemType Directory -Path $advancedSystemInformationFolder
        New-Item -ItemType Directory -Path $powerManagementFolder
        New-Item -ItemType Directory -Path $userGroupInformationFolder
        New-Item -ItemType Directory -Path $backupRestoreInformationFolder

        # Log Folder
        if ($logFolderCreated -eq $true) {
            Log-Message "Created Log Folder: $reportFolder"
        }
        elseif ($logFolderRecreated -eq $true) {
            Log-Message "Recreated Log Folder: $reportFolder"
        }
        else {
            Log-Message "Log folder already exists at $reportFolder"
        }

        # Log Transcript
        if ($transcriptCreated -eq $true) {
            Log-Message "Created Transcript File: $transcriptFile"
        }
        elseif ($transcriptRecreated -eq $true) {
            Log-Message "Recreated Transcript File: $transcriptFile"
        }
        else {
            Log-Message "Transcript file already exists at $transcriptFile"
        }

        # Log Empty Folder
        if ($emptyFolderCreated -eq $true) {
            Log-Message "Created Empty Folder: $emptyFolder"
        }
        elseif ($emptyFolderRecreated -eq $true) {
            Log-Message "Recreated Empty Folder: $emptyFolder"
        }
        else {
            Log-Message "Empty folder already exists at $emptyFolder"
        }

        # Log Folder
        Log-Message "Created README File: $reportFolder\README.txt"
        Log-Message "Created Hardware Information Folder: $hardwareInformationFolder"
        Log-Message "Created Operating System Details Folder: $operatingSystemDetailsFolder"
        Log-Message "Created Network Configuration Diagnostics Folder: $networkConfigurationDiagnosticsFolder"
        Log-Message "Created Disk Storage Information Folder: $diskStorageInformationFolder"
        Log-Message "Created System Security Audit Folder: $systemSecurityAuditFolder"
        Log-Message "Created System Application Logs Folder: $systemApplicationLogsFolder"
        Log-Message "Created Services Processes Folder: $servicesProcessesFolder"
        Log-Message "Created Installed Software Drivers Folder: $installedSoftwareDriversFolder"
        Log-Message "Created System Performance Diagnostics Folder: $systemPerformanceDiagnosticsFolder"
        Log-Message "Created Advanced System Information Folder: $advancedSystemInformationFolder"
        Log-Message "Created Power Management Folder: $powerManagementFolder"
        Log-Message "Created User Group Information Folder: $userGroupInformationFolder"
        Log-Message "Created Backup Restore Information Folder: $backupRestoreInformationFolder"

        # Xperf Capture Time (in seconds)
        $XperfCaptureTime = 10
            
        # Xperf output file
        $xperfOutputFile = "$systemPerformanceDiagnosticsFolder\xperf_output.etl"

        # Xperf output text file
        $xperfOutputTextFile = "$systemPerformanceDiagnosticsFolder\xperf_output.txt"

        # GPResult for Group Policy Report
        GPResult /H "$systemSecurityAuditFolder\GPReport.html"
        Log-Message "Generated Group Policy Report"

        # System Information
        systeminfo | Out-File "$advancedSystemInformationFolder\systeminfo.txt"
        Log-Message "Collected system information"

        # Disk Information
        Get-Disk | Out-File "$diskStorageInformationFolder\diskinfo.txt"
        Log-Message "Collected disk information"

        # Physical Disk Information
        Get-PhysicalDisk | Get-StorageReliabilityCounter | Out-File "$diskStorageInformationFolder\physicaldiskinfo.txt"
        Log-Message "Collected physical disk information"

        # ACL Information
        Get-Acl -Path $systemDrive | Out-File "$systemSecurityAuditFolder\aclinfo.txt"

        # Windows Update Hotfixes
        Get-HotFix | Out-File "$operatingSystemDetailsFolder\hotfixes.txt"

        # Windows Update Logs
        Get-WindowsUpdateLog | Out-File "$operatingSystemDetailsFolder\windowsupdatelog.txt"

        # Network Configuration
        Get-NetIPConfiguration | Out-File "$networkConfigurationDiagnosticsFolder\networkconfig.txt"
        Log-Message "Collected network configuration"

        # Network Adapter Information
        Get-NetAdapter | Out-File "$networkConfigurationDiagnosticsFolder\netadapterinfo.txt"
        Log-Message "Collected network adapter information"

        # Installed Programs
        Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Out-File "$installedSoftwareDriversFolder\installedprograms.txt"
        Log-Message "Collected installed programs"

        # Windows Services
        Get-Service | Out-File "$servicesProcessesFolder\services.txt"
        Log-Message "Collected Windows services"

        # Process List
        Get-Process | Out-File "$servicesProcessesFolder\processlist.txt"
        Log-Message "Collected process list"

        # Event Logs
        Get-EventLog -LogName System | Out-File "$systemApplicationLogsFolder\systemeventlog.txt"
        Get-EventLog -LogName Application | Out-File "$systemApplicationLogsFolder\applicationeventlog.txt"
        Get-EventLog -LogName Security | Out-File "$systemApplicationLogsFolder\securityeventlog.txt"
        Log-Message "Collected event logs"

        # Hardware Information
        Get-WmiObject Win32_Processor | Out-File "$hardwareInformationFolder\cpuinfo.txt"
        Log-Message "Collected hardware information"
        Get-WmiObject Win32_PhysicalMemory | Out-File "$hardwareInformationFolder\memoryinfo.txt"
        Log-Message "Collected hardware information"
        Get-WmiObject Win32_DiskDrive | Out-File "$hardwareInformationFolder\driveinfo.txt"
        Log-Message "Collected hardware information"
        Get-WmiObject Win32_VideoController | Out-File "$hardwareInformationFolder\gpuinfo.txt"
        Log-Message "Collected hardware information"
        

        # Security Settings
        Get-LocalGroup | Out-File "$systemSecurityAuditFolder\localgroups.txt"
        Log-Message "Collected security settings"
        Get-LocalUser | Out-File "$systemSecurityAuditFolder\localusers.txt"
        Log-Message "Collected security settings"

        # System Uptime
        (Get-Uptime).ToString() | Out-File "$systemPerformanceDiagnosticsFolder\systemuptime.txt"
        Log-Message "Collected system uptime"

        # Firewall Rules
        Get-NetFirewallRule | Out-File "$systemSecurityAuditFolder\firewallrules.txt"
        Log-Message "Collected firewall rules"

        # Scheduled Tasks
        Get-ScheduledTask | Out-File "$systemPerformanceDiagnosticsFolder\scheduledtasks.txt"
        Log-Message "Collected scheduled tasks"

        # Environment Variables
        Get-ChildItem Env: | Out-File "$advancedSystemInformationFolder\environmentvariables.txt"
        Log-Message "Collected environment variables"

        # BIOS Information
        Get-WmiObject Win32_BIOS | Out-File "$advancedSystemInformationFolder\biosinfo.txt"
        Log-Message "Collected BIOS information"

        # Operating System Details
        Get-WmiObject Win32_OperatingSystem | Format-List * | Out-File "$operatingSystemDetailsFolder\osdetails.txt"
        Log-Message "Collected operating system details"

        # System Restore Information
        Get-ComputerRestorePoint | Out-File "$backupRestoreInformationFolder\systemrestoreinfo.txt"
        Log-Message "Collected system restore information"

        # Logical Disk Information
        Get-WmiObject Win32_LogicalDisk | Format-List * | Out-File "$diskStorageInformationFolder\logicaldiskinfo.txt"
        Log-Message "Collected logical disk information"

        # Active Network Connections
        Get-NetTCPConnection | Out-File "$networkConfigurationDiagnosticsFolder\netconnections.txt"
        Log-Message "Collected active network connections"

        # User Account Details
        Get-WmiObject Win32_UserAccount | Format-List * | Out-File "$userGroupInformationFolder\useraccounts.txt"
        Log-Message "Collected user account details"

        # System Security Settings
        secedit /export /cfg "$systemSecurityAuditFolder\securitysettings.cfg"
        Log-Message "Collected system security settings"

        # Driver Information
        Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Out-File "$installedSoftwareDriversFolder\driverinfo.txt"
        Log-Message "Collected driver information"

        # Advanced Disk Management Information
        Get-Partition | Out-File "$diskStorageInformationFolder\diskpartitions.txt"
        Log-Message "Collected advanced disk management information"
        Get-Volume | Out-File "$diskStorageInformationFolder\volumeinfo.txt"
        Log-Message "Collected advanced disk management information"

        # Detailed Version and Update Information
        Get-WmiObject Win32_QuickFixEngineering | Out-File "$operatingSystemDetailsFolder\installedupdates.txt"
        Log-Message "Collected detailed version and update information"
        [System.Environment]::OSVersion.Version | Out-File "$operatingSystemDetailsFolder\osversion.txt"
        Log-Message "Collected detailed version and update information"

        # Detailed Network Profile Information
        Get-NetConnectionProfile | Out-File "$networkConfigurationDiagnosticsFolder\networkprofiles.txt"
        Log-Message "Collected detailed network profile information"

        # Power Plan Information
        powercfg /list | Out-File "$powerManagementFolder\powerplans.txt"
        Log-Message "Collected power plan information"

        # Detailed Environment Information
        Get-ComputerInfo | Out-File "$advancedSystemInformationFolder\computerinfo.txt"
        Log-Message "Collected detailed environment information"

        # Battery Report
        if ((Get-WmiObject Win32_Battery)) {
            powercfg /batteryreport /output "$powerManagementFolder\batteryreport.html"
            Log-Message "Generated battery report"
        }

        # DirectX Diagnostic Report
        dxdiag /t "$operatingSystemDetailsFolder\dxdiag.txt"
        Log-Message "Generated DirectX diagnostic report"

        # System File Checker Report
        sfc /scannow | Out-File "$systemPerformanceDiagnosticsFolder\sfc.txt"
        Log-Message "Generated System File Checker report"

        # DISM Scan Report
        DISM /Online /Cleanup-Image /ScanHealth | Out-File "$systemPerformanceDiagnosticsFolder\dism.txt"
        Log-Message "Generated DISM scan report"

        # System Security Configuration
        Get-WmiObject Win32_LogicalShareSecuritySetting | Out-File "$systemSecurityAuditFolder\sharesecuritysettings.txt"
        Log-Message "Collected system security configuration"
        Get-WmiObject Win32_NTEventlogFile | Out-File "$systemSecurityAuditFolder\eventlogsettings.txt"
        Log-Message "Collected system security configuration"

        # Advanced Network Diagnostics
        Test-NetConnection | Out-File "$networkConfigurationDiagnosticsFolder\networkdiagnostics.txt"
        Log-Message "Collected advanced network diagnostics"
        Get-NetRoute | Out-File "$networkConfigurationDiagnosticsFolder\netroutes.txt"
        Log-Message "Collected advanced network diagnostics"

        # Detailed Driver Information
        Get-WindowsDriver -Online | Out-File "$installedSoftwareDriversFolder\windowsdrivers.txt"
        Log-Message "Collected detailed driver information"

        # Detailed Service Configuration
        Get-WmiObject Win32_Service | Out-File "$servicesProcessesFolder\serviceconfigurations.txt"
        Log-Message "Collected detailed service configuration"

        # User Login History
        Get-WmiObject Win32_NetworkLoginProfile | Out-File "$userGroupInformationFolder\userloginhistory.txt"
        Log-Message "Collected user login history"

        # Installed Codecs
        Get-WmiObject Win32_CodecFile | Out-File "$installedSoftwareDriversFolder\installedcodecs.txt"
        Log-Message "Collected installed codecs"

        # System Environmental Variables
        Get-WmiObject Win32_Environment | Out-File "$advancedSystemInformationFolder\systemenvironmentvariables.txt"
        Log-Message "Collected system environmental variables"

        # Detailed Network Adapter Information
        Get-WmiObject Win32_NetworkAdapter | Out-File "$networkConfigurationDiagnosticsFolder\networkadapterinfo.txt"
        Log-Message "Collected detailed network adapter information"

        # Detailed Network Adapter Configuration
        Get-WmiObject Win32_NetworkAdapterConfiguration | Out-File "$networkConfigurationDiagnosticsFolder\networkadapterconfig.txt"
        Log-Message "Collected detailed network adapter configuration"

        # Detailed Network Adapter Statistics
        Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkAdapter | Out-File "$networkConfigurationDiagnosticsFolder\networkadapterstats.txt"
        Log-Message "Collected detailed network adapter statistics"

        # Advanced Security Audit Checks
        Get-WmiObject -Class Win32_LogonSession | Out-File "$systemSecurityAuditFolder\logonsessions.txt"
        Log-Message "Collected advanced security audit checks"
        Get-WmiObject -Class Win32_SecurityDescriptor | Out-File "$systemSecurityAuditFolder\securitydescriptors.txt"
        Log-Message "Collected advanced security audit checks"
        Get-WmiObject -Class Win32_SystemAccount | Out-File "$systemSecurityAuditFolder\systemaccounts.txt"
        Log-Message "Collected advanced security audit checks"

        # Detailed Hardware Configuration
        Get-CimInstance -ClassName Win32_ComputerSystem | Format-List * | Out-File "$hardwareInformationFolder\hardwareconfiguration.txt"
        Log-Message "Collected detailed hardware configuration"

        # Windows Licensing Status
        cscript //Nologo $systemDrive\Windows\System32\slmgr.vbs /dli | Out-File "$operatingSystemDetailsFolder\windowslicensestatus.txt"
        Log-Message "Collected Windows licensing status"

        Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' } | Out-File "$hardwareInformationFolder\usbdevices.txt"
        Log-Message "Collected USB device information"

        # Detailed System Configuration
        Get-WmiObject Win32_ComputerSystemProduct | Out-File "$advancedSystemInformationFolder\computerproduct.txt"

        # Collect CPU Usage
        $cpuInfo = Get-Counter -Counter "\Processor(*)\% Processor Time" -SampleInterval 1 -MaxSamples 1

        # Write per-core CPU usage to a file
        foreach ($cpu in $cpuInfo.CounterSamples) {
            if ($cpu.InstanceName -ne "_Total" -and $cpu.InstanceName -ne "Idle") {
                "Core $($cpu.InstanceName) Usage: $($cpu.CookedValue)%" | Out-File -FilePath "$systemPerformanceDiagnosticsFolder\cpuload.txt" -Append
            }
        }

        # Stop Xperf data collection incase it is already running
        Start-Process xperf.exe -ArgumentList "-stop" -NoNewWindow -Wait
        Log-Message "Stopped Xperf data collection"

        # Start Xperf data collection
        Start-Process xperf.exe -ArgumentList "-on DiagEasy+PROFILE -BufferSize 512 /f $xperfOutputFile" -NoNewWindow -Wait
        Log-Message "Started Xperf data collection"

        # Pause for Xperf data collection
        Start-Sleep -Seconds $XperfCaptureTime
        Log-Message "Sleeping for $XperfCaptureTime seconds"

        # Stop Xperf data collection
        Start-Process xperf.exe -ArgumentList "-stop" -NoNewWindow -Wait
        Log-Message "Stopped Xperf data collection"

        # Convert Xperf output to a text file
        Start-Process xperf.exe -ArgumentList "-i $xperfOutputFile -o $xperfOutputTextFile -a dumper" -NoNewWindow -Wait
        Log-Message "Converted Xperf output to a text file @ $xperfOutputTextFile"

        # Open the report folder
        Invoke-Item -Path $reportFolder

        # Display a message box
        [NativeMethods]::MessageBox([IntPtr]::Zero, "System report generated successfully.", "GSR", 0x00000040)
    }
}
catch {
    Log-Message "Error: $_.Exception.Message"
    Log-Message "Error Details: $_"
    Log-Message "Error Location: $($_.InvocationInfo.ScriptName) at line $($_.InvocationInfo.ScriptLineNumber), column $($_.InvocationInfo.OffsetInLine)"
}
finally {
    # Stop Transcript
    Stop-Transcript
}

#----------------------------------------------
# End of Script
#----------------------------------------------
