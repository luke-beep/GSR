# =================================================================== #
#  *-*-*   +   -   *   +   -*-*   +   -   *   +   -*-*   +   -   *    #
#  +   *   -   +   *   -   +   *   -   +   *   -   +   *   -   +   *  #
#  -*-*   +   -   *   +   -*-*   +   -   *   +   -*-*   +   -   *     #
#  +   *   -   +   *   -   +   *   -   +   *   -   +   *   -   +   *  #
#  *-*-*   +   -   *   +   -*-*   +   -   *   +   -*-*   +   -   *    #
# =================================================================== #
#                   Created by Azrael (LukeHjo)                       #
#                           21/12/2023                                #
# =================================================================== #

function Log-Message {
    param (
        [string]$Message
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage
}

# Script Name
$scriptName = "GenerateSystemReport.ps1"

# Script Version
$scriptVersion = "1.0.0"

# Script Description
$scriptDescription = "This script generates a system report for troubleshooting purposes."

# Script Author
$scriptAuthor = "Azrael (LukeHjo)"

# Script Date
$scriptDate = "21/12/2023"

# Script License
$scriptLicense = "MIT"

# Script Repository
$scriptRepository = ""

# System Drive
$systemDrive = $env:SystemDrive

# Empty Folder
$emptyFolder = "$systemDrive\Empty"

# Report Folder
$reportFolder = "$systemDrive\SystemReports"

# Debug Folder
$debugFolder = "$reportFolder\Debug"

# Debug Mode
$debug = $false

# Xperf Capture Time (in seconds)
$XperfCaptureTime = 10
    
# Xperf output file
$xperfOutputFile = "$reportFolder\xperf_output.etl"

# Xperf output text file
$xperfOutputTextFile = "$reportFolder\xperf_output.txt"

# Transcript File
$transcriptFile = "$reportFolder\debug.txt"
try {
    # Create Transcript File
    if (!(Test-Path $transcriptFile)) {
        New-Item -ItemType File -Path $transcriptFile
        Log-Message "Transcript file created at $transcriptFile"
    }
    else {
        Remove-Item -Force $transcriptFile
        New-Item -ItemType File -Path $transcriptFile
        Log-Message "Transcript file recreated at $transcriptFile"
    }

    # Create Empty Folder
    if (!(Test-Path $emptyFolder)) {
        New-Item -ItemType Directory -Path $emptyFolder
        Log-Message "Empty folder created at $emptyFolder"
    }
    else {
        Remove-Item -Recurse -Force $emptyFolder
        New-Item -ItemType Directory -Path $emptyFolder
        Log-Message "Empty folder recreated at $emptyFolder"
    }

    # Create Report Folder
    if (!(Test-Path $reportFolder)) {
        New-Item -ItemType Directory -Path $reportFolder
        Log-Message "Report folder created at $reportFolder"
    }
    else {
        Start-Process robocopy -ArgumentList "/mir $emptyFolder $reportFolder" -NoNewWindow -Wait
        Remove-Item -Recurse -Force $reportFolder
        Log-Message "Report folder recreated at $reportFolder"
    }

    # Start Transcript
    Log-Message "Starting Transcript"
    Start-Transcript -Path $transcriptFile -Append

    if ($debug -eq $true) {
        Log-Message "Debug mode enabled"
        # Create Debug Folder
        if (!(Test-Path $debugFolder)) {
            New-Item -ItemType Directory -Path $debugFolder
        }
        else {
            Start-Process robocopy -ArgumentList "/mir $emptyFolder $debugFolder" -NoNewWindow -Wait
        }

        # Start Debugging
    }
    else {
        # Start System Report
        Log-Message "Starting System Report"

        # GPResult for Group Policy Report
        GPResult /H "$reportFolder\GPReport.html"
        Log-Message "Generated Group Policy Report"

        # System Information
        systeminfo | Out-File "$reportFolder\systeminfo.txt"
        Log-Message "Collected system information"

        # Disk Information
        Get-Disk | Out-File "$reportFolder\diskinfo.txt"
        Log-Message "Collected disk information"

        # Network Configuration
        Get-NetIPConfiguration | Out-File "$reportFolder\networkconfig.txt"
        Log-Message "Collected network configuration"

        # Network Adapter Information
        Get-NetAdapter | Out-File "$reportFolder\netadapterinfo.txt"
        Log-Message "Collected network adapter information"

        # Installed Programs
        Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Out-File "$reportFolder\installedprograms.txt"
        Log-Message "Collected installed programs"

        # Windows Services
        Get-Service | Out-File "$reportFolder\services.txt"
        Log-Message "Collected Windows services"

        # Process List
        Get-Process | Out-File "$reportFolder\processlist.txt"
        Log-Message "Collected process list"

        # Event Logs
        Get-EventLog -LogName System | Out-File "$reportFolder\systemeventlog.txt"
        Get-EventLog -LogName Application | Out-File "$reportFolder\applicationeventlog.txt"
        Get-EventLog -LogName Security | Out-File "$reportFolder\securityeventlog.txt"
        Log-Message "Collected event logs"

        # Hardware Information
        Get-WmiObject Win32_Processor | Out-File "$reportFolder\cpuinfo.txt"
        Log-Message "Collected hardware information"
        Get-WmiObject Win32_PhysicalMemory | Out-File "$reportFolder\memoryinfo.txt"
        Log-Message "Collected hardware information"
        Get-WmiObject Win32_DiskDrive | Out-File "$reportFolder\driveinfo.txt"
        Log-Message "Collected hardware information"
        Get-WmiObject Win32_VideoController | Out-File "$reportFolder\gpuinfo.txt"
        Log-Message "Collected hardware information"
        

        # Security Settings
        Get-LocalGroup | Out-File "$reportFolder\localgroups.txt"
        Log-Message "Collected security settings"
        Get-LocalUser | Out-File "$reportFolder\localusers.txt"
        Log-Message "Collected security settings"

        # System Uptime
        (Get-Uptime).ToString() | Out-File "$reportFolder\systemuptime.txt"
        Log-Message "Collected system uptime"

        # Firewall Rules
        Get-NetFirewallRule | Out-File "$reportFolder\firewallrules.txt"
        Log-Message "Collected firewall rules"

        # Scheduled Tasks
        Get-ScheduledTask | Out-File "$reportFolder\scheduledtasks.txt"
        Log-Message "Collected scheduled tasks"

        # Environment Variables
        Get-ChildItem Env: | Out-File "$reportFolder\environmentvariables.txt"
        Log-Message "Collected environment variables"

        # BIOS Information
        Get-WmiObject Win32_BIOS | Out-File "$reportFolder\biosinfo.txt"
        Log-Message "Collected BIOS information"

        # Operating System Details
        Get-WmiObject Win32_OperatingSystem | Format-List * | Out-File "$reportFolder\osdetails.txt"
        Log-Message "Collected operating system details"

        # System Restore Information
        Get-ComputerRestorePoint | Out-File "$reportFolder\systemrestoreinfo.txt"
        Log-Message "Collected system restore information"

        # Logical Disk Information
        Get-WmiObject Win32_LogicalDisk | Format-List * | Out-File "$reportFolder\logicaldiskinfo.txt"
        Log-Message "Collected logical disk information"

        # Active Network Connections
        Get-NetTCPConnection | Out-File "$reportFolder\netconnections.txt"
        Log-Message "Collected active network connections"

        # User Account Details
        Get-WmiObject Win32_UserAccount | Format-List * | Out-File "$reportFolder\useraccounts.txt"
        Log-Message "Collected user account details"

        # System Security Settings
        secedit /export /cfg "$reportFolder\securitysettings.cfg"
        Log-Message "Collected system security settings"

        # Driver Information
        Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Out-File "$reportFolder\driverinfo.txt"
        Log-Message "Collected driver information"

        # Advanced Disk Management Information
        Get-Partition | Out-File "$reportFolder\diskpartitions.txt"
        Log-Message "Collected advanced disk management information"
        Get-Volume | Out-File "$reportFolder\volumeinfo.txt"
        Log-Message "Collected advanced disk management information"

        # Detailed Version and Update Information
        Get-WmiObject Win32_QuickFixEngineering | Out-File "$reportFolder\installedupdates.txt"
        Log-Message "Collected detailed version and update information"
        [System.Environment]::OSVersion.Version | Out-File "$reportFolder\osversion.txt"
        Log-Message "Collected detailed version and update information"

        # Detailed Network Profile Information
        Get-NetConnectionProfile | Out-File "$reportFolder\networkprofiles.txt"
        Log-Message "Collected detailed network profile information"

        # Power Plan Information
        powercfg /list | Out-File "$reportFolder\powerplans.txt"
        Log-Message "Collected power plan information"

        # Detailed Environment Information
        Get-ComputerInfo | Out-File "$reportFolder\computerinfo.txt"
        Log-Message "Collected detailed environment information"

        # Battery Report
        if ((Get-WmiObject Win32_Battery)) {
            powercfg /batteryreport /output "$reportFolder\batteryreport.html"
            Log-Message "Generated battery report"
        }

        # DirectX Diagnostic Report
        dxdiag /t "$reportFolder\dxdiag.txt"
        Log-Message "Generated DirectX diagnostic report"

        # System File Checker Report
        sfc /scannow | Out-File "$reportFolder\sfc.txt"
        Log-Message "Generated System File Checker report"

        # DISM Scan Report
        DISM /Online /Cleanup-Image /ScanHealth | Out-File "$reportFolder\dism.txt"
        Log-Message "Generated DISM scan report"

        # System Security Configuration
        Get-WmiObject Win32_LogicalShareSecuritySetting | Out-File "$reportFolder\sharesecuritysettings.txt"
        Log-Message "Collected system security configuration"
        Get-WmiObject Win32_NTEventlogFile | Out-File "$reportFolder\eventlogsettings.txt"
        Log-Message "Collected system security configuration"

        # Advanced Network Diagnostics
        Test-NetConnection | Out-File "$reportFolder\networkdiagnostics.txt"
        Log-Message "Collected advanced network diagnostics"
        Get-NetRoute | Out-File "$reportFolder\netroutes.txt"
        Log-Message "Collected advanced network diagnostics"

        # Detailed Driver Information
        Get-WindowsDriver -Online | Out-File "$reportFolder\windowsdrivers.txt"
        Log-Message "Collected detailed driver information"

        # Detailed Service Configuration
        Get-WmiObject Win32_Service | Out-File "$reportFolder\serviceconfigurations.txt"
        Log-Message "Collected detailed service configuration"

        # User Login History
        Get-WmiObject Win32_NetworkLoginProfile | Out-File "$reportFolder\userloginhistory.txt"
        Log-Message "Collected user login history"

        # Installed Codecs
        Get-WmiObject Win32_CodecFile | Out-File "$reportFolder\installedcodecs.txt"
        Log-Message "Collected installed codecs"

        # System Environmental Variables
        Get-WmiObject Win32_Environment | Out-File "$reportFolder\systemenvironmentvariables.txt"
        Log-Message "Collected system environmental variables"

        # Detailed Network Adapter Information
        Get-WmiObject Win32_NetworkAdapter | Out-File "$reportFolder\networkadapterinfo.txt"
        Log-Message "Collected detailed network adapter information"

        # Detailed Network Adapter Configuration
        Get-WmiObject Win32_NetworkAdapterConfiguration | Out-File "$reportFolder\networkadapterconfig.txt"
        Log-Message "Collected detailed network adapter configuration"

        # Detailed Network Adapter Statistics
        Get-WmiObject Win32_PerfFormattedData_Tcpip_NetworkAdapter | Out-File "$reportFolder\networkadapterstats.txt"
        Log-Message "Collected detailed network adapter statistics"

        # Advanced Security Audit Checks
        Get-WmiObject -Class Win32_LogonSession | Out-File "$reportFolder\logonsessions.txt"
        Log-Message "Collected advanced security audit checks"
        Get-WmiObject -Class Win32_SecurityDescriptor | Out-File "$reportFolder\securitydescriptors.txt"
        Log-Message "Collected advanced security audit checks"
        Get-WmiObject -Class Win32_SystemAccount | Out-File "$reportFolder\systemaccounts.txt"
        Log-Message "Collected advanced security audit checks"

        # Detailed Hardware Configuration
        Get-CimInstance -ClassName Win32_ComputerSystem | Format-List * | Out-File "$reportFolder\hardwareconfiguration.txt"
        Log-Message "Collected detailed hardware configuration"

        # Windows Licensing Status
        cscript //Nologo $systemDrive\Windows\System32\slmgr.vbs /dli | Out-File "$reportFolder\windowslicensestatus.txt"
        Log-Message "Collected Windows licensing status"

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

        Invoke-Item -Path $reportFolder
    }
}
catch {

}
finally {
    # Stop Transcript
    Stop-Transcript
}