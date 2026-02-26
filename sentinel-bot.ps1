<#
.SYNOPSIS
    AD Sentinel Bot - Enhanced Monitoring Framework
.DESCRIPTION
    Core functionality for monitoring Active Directory group memberships.
    This version includes group discovery, membership tracking, change detection,
    advanced reporting, and email notifications.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$GroupNames,
    
    [string]$DataPath = "C:\ADSentinelBot\Data",
    
    [switch]$UseLegacyADSNAPIN,
    
    [string]$ReportPath = "C:\ADSentinelBot\Reports",
    
    [switch]$EnableEmailNotifications,
    
    [string]$SMTPServer,
    
    [string]$EmailFrom,
    
    [string[]]$EmailTo,
    
    [string]$EmailSubject = "AD Sentinel Bot - Group Changes Detected"
)

# Core configuration
$ScriptVersion = "1.1.0"
$ScriptName = "AD Sentinel Bot"

Write-Host "🛡️ $ScriptName v$ScriptVersion - Starting Enhanced Monitoring" -ForegroundColor Cyan

function Write-LogEntry {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    static $lastMessage = $null
    static $lastTimestamp = $null
    $currentTime = Get-Date
    
    if ($Message -eq $lastMessage -and 
        $lastTimestamp -and 
        ($currentTime - $lastTimestamp).TotalSeconds -lt 5) {
        return
    }
    
    $lastMessage = $Message
    $lastTimestamp = $currentTime
    $color = switch($Level) {
        "ERROR"    { 'Red' }
        "WARNING"  { 'Yellow' }
        "SUCCESS"  { 'Green' }
        "INFO"     { 'Gray' }
        "DEBUG"    { 'DarkGray' }
        default    { 'White' }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    $logDir = Join-Path $DataPath "Logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    $logFile = Join-Path $logDir "adsentinel_$(Get-Date -Format 'yyyyMMdd').log"
    $oldLogs = Get-ChildItem -Path $logDir -Filter "adsentinel_*.log" | 
               Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }
    
    if ($oldLogs) {
        $oldLogs | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "$($oldLogs.Count) old log files removed (older than 30 days)" -ForegroundColor DarkGray
    }
    try {
        Add-Content -Path $logFile -Value $logEntry -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        $tempLog = Join-Path $env:TEMP "adsentinel_fallback.log"
        Write-Host "Failed to write to main log, using fallback: $tempLog" -ForegroundColor Yellow
        Add-Content -Path $tempLog -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Test-ADConnectivity {
    [CmdletBinding()]
    param (
        [string]$Domain = $env:USERDNSDOMAIN,
        [int]$TimeoutSeconds = 10,
        [switch]$DetailedOutput
    )

    begin {
        Write-LogEntry "Starting Active Directory connectivity test..." "DEBUG"
        $startTime = Get-Date
    }

    process {
        try {
            Write-LogEntry "Checking DNS resolution for domain: $Domain" "DEBUG"
            $dnsResult = Resolve-DnsName -Name $Domain -Type A -ErrorAction Stop
            Write-LogEntry "DNS resolution successful: $($dnsResult.IPAddress -join ', ')" "SUCCESS"
            if ($UseLegacyADSNAPIN) {
                Write-LogEntry "Using legacy QAD cmdlets for AD connectivity test" "DEBUG"
                $testResult = Get-QADObject -Identity "RootDSE" -Timeout $TimeoutSeconds -ErrorAction Stop
            }
            else {
                Write-LogEntry "Using ActiveDirectory module for AD connectivity test" "DEBUG"
                if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                    throw "ActiveDirectory module is not installed or available"
                }
                $params = @{
                    ErrorAction = 'Stop'
                    Server = $Domain
                }
                if ($TimeoutSeconds) {
                    $params['Timeout'] = $TimeoutSeconds
                }
                
                $testResult = Get-ADDomain @params
            }

            $endTime = Get-Date
            $duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)

            Write-LogEntry "Active Directory connectivity test successful (duration: $duration sec)" "SUCCESS"
            
            if ($DetailedOutput) {
                return @{
                    Success = $true
                    Domain = $testResult.Name
                    Forest = $testResult.Forest
                    DomainMode = $testResult.DomainMode
                    PDCEmulator = $testResult.PDCEmulator
                    Duration = $duration
                    Timestamp = $endTime
                }
            }
            else {
                return $true
            }
        }
        catch {
            $endTime = Get-Date
            $duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
            
            $errorMessage = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $errorMessage += " | Inner: $($_.Exception.InnerException.Message)"
            }

            Write-LogEntry "Active Directory connectivity test failed after $duration sec: $errorMessage" "ERROR"
            Write-LogEntry "Exception type: $($_.Exception.GetType().FullName)" "DEBUG"

            if ($DetailedOutput) {
                return @{
                    Success = $false
                    Error = $errorMessage
                    ExceptionType = $_.Exception.GetType().FullName
                    Duration = $duration
                    Timestamp = $endTime
                }
            }
            else {
                return $false
            }
        }
    }

    end {
        Write-LogEntry "AD connectivity test completed" "DEBUG"
    }
}


# Function to initialize AD connection
function Initialize-ADConnection {
    if ($UseLegacyADSNAPIN) {
        Write-LogEntry "Using legacy Quest Active Directory Snapin" "DEBUG"
        if (-not (Get-PSSnapin -Name Quest.ActiveRoles.ADManagement -ErrorAction SilentlyContinue)) {
            Add-PSSnapin Quest.ActiveRoles.ADManagement -ErrorAction Stop
            Write-LogEntry "Quest Active Directory Snapin loaded successfully" "SUCCESS"
        }
    } else {
        Write-LogEntry "Using Microsoft ActiveDirectory module" "DEBUG"
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-LogEntry "ActiveDirectory module imported successfully" "SUCCESS"
    }
}

# Function to resolve group identity
function Resolve-ADGroup {
    param([string]$GroupIdentifier)
    
    try {
        Write-LogEntry "Resolving group: $GroupIdentifier" "DEBUG"
        if ($UseLegacyADSNAPIN) {
            $group = Get-QADGroup -Identity $GroupIdentifier -ErrorAction Stop
        } else {
            $group = Get-ADGroup -Identity $GroupIdentifier -Properties DistinguishedName, SID -ErrorAction Stop
        }
        Write-LogEntry "Successfully resolved group: $($group.Name)" "SUCCESS"
        return $group
    }
    catch {
        Write-LogEntry "Cannot resolve group: $GroupIdentifier - $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Function to capture group membership snapshot
function Get-GroupMembershipSnapshot {
    param([object]$ADGroup)
    
    $members = @()
    
    try {
        Write-LogEntry "Capturing membership snapshot for group: $($ADGroup.Name)" "DEBUG"
        
        if ($UseLegacyADSNAPIN) {
            $rawMembers = Get-QADGroupMember -Identity $ADGroup.DistinguishedName -ErrorAction Stop
        } else {
            $rawMembers = Get-ADGroupMember -Identity $ADGroup.DistinguishedName -ErrorAction Stop
        }
        
        foreach ($member in $rawMembers) {
            $memberInfo = [PSCustomObject]@{
                ObjectClass = $member.ObjectClass
                SamAccountName = $member.SamAccountName
                DisplayName = if ($member.ObjectClass -eq 'user') { 
                    if ($UseLegacyADSNAPIN) { $member.DisplayName } else { $member.Name }
                } else { 
                    $member.Name 
                }
                DistinguishedName = $member.DistinguishedName
                ObjectGUID = if ($member.ObjectGUID) { $member.ObjectGUID.ToString() } else { 'N/A' }
                CapturedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            $members += $memberInfo
        }
        
        Write-LogEntry "Captured $($members.Count) members from group: $($ADGroup.Name)" "INFO"
    }
    catch {
        Write-LogEntry "Group appears to be empty or inaccessible: $($ADGroup.Name) - $($_.Exception.Message)" "WARNING"
    }
    
    # Handle empty groups
    if ($members.Count -eq 0) {
        Write-LogEntry "Group is empty: $($ADGroup.Name)" "INFO"
        $members += [PSCustomObject]@{
            ObjectClass = "EmptyGroup"
            SamAccountName = "EMPTY_GROUP_PLACEHOLDER"
            DisplayName = "No members in group"
            DistinguishedName = ""
            ObjectGUID = ""
            CapturedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
    }
    
    return $members
}

# Function to compare snapshots and detect changes
function Compare-GroupSnapshots {
    param(
        [array]$CurrentSnapshot,
        [array]$PreviousSnapshot
    )
    
    $detectedChanges = @()
    
    Write-LogEntry "Comparing group snapshots..." "DEBUG"
    
    # Handle initial snapshot case
    if (-not $PreviousSnapshot) {
        Write-LogEntry "No previous snapshot found - this is the initial baseline" "INFO"
        return $detectedChanges
    }
    
    # Convert to lookup tables for easier comparison
    $currentLookup = @{}
    $previousLookup = @{}
    
    $CurrentSnapshot | ForEach-Object { 
        if ($_.SamAccountName -ne "EMPTY_GROUP_PLACEHOLDER") {
            $currentLookup[$_.DistinguishedName] = $_ 
        }
    }
    
    $PreviousSnapshot | ForEach-Object { 
        if ($_.SamAccountName -ne "EMPTY_GROUP_PLACEHOLDER") {
            $previousLookup[$_.DistinguishedName] = $_ 
        }
    }
    
    # Detect new members (in current but not in previous)
    foreach ($dn in $currentLookup.Keys) {
        if (-not $previousLookup.ContainsKey($dn)) {
            $change = [PSCustomObject]@{
                ChangeType = "MemberAdded"
                Member = $currentLookup[$dn]
                ChangeTime = Get-Date
                ChangeDescription = "User/Group added to group"
            }
            $detectedChanges += $change
            Write-LogEntry "Detected new member: $($currentLookup[$dn].SamAccountName)" "DEBUG"
        }
    }
    
    # Detect removed members (in previous but not in current)
    foreach ($dn in $previousLookup.Keys) {
        if (-not $currentLookup.ContainsKey($dn)) {
            $change = [PSCustomObject]@{
                ChangeType = "MemberRemoved"
                Member = $previousLookup[$dn]
                ChangeTime = Get-Date
                ChangeDescription = "User/Group removed from group"
            }
            $detectedChanges += $change
            Write-LogEntry "Detected removed member: $($previousLookup[$dn].SamAccountName)" "DEBUG"
        }
    }
    
    # Handle empty group transitions
    $wasEmpty = $PreviousSnapshot[0].SamAccountName -eq "EMPTY_GROUP_PLACEHOLDER"
    $isEmpty = $CurrentSnapshot[0].SamAccountName -eq "EMPTY_GROUP_PLACEHOLDER"
    
    if ($wasEmpty -and -not $isEmpty) {
        Write-LogEntry "Group transitioned from empty to having members" "INFO"
    }
    elseif (-not $wasEmpty -and $isEmpty) {
        Write-LogEntry "Group transitioned from having members to empty" "INFO"
    }
    
    Write-LogEntry "Comparison completed: $($detectedChanges.Count) changes detected" "DEBUG"
    return $detectedChanges
}

# Function to save snapshot to storage
function Save-GroupSnapshot {
    param(
        [object]$ADGroup,
        [array]$Snapshot,
        [string]$StoragePath
    )
    
    $domain = ($ADGroup.DistinguishedName -split ',DC=')[1]
    $safeGroupName = $ADGroup.Name -replace '[^a-zA-Z0-9]', '_'
    $snapshotFile = Join-Path $StoragePath "${domain}_${safeGroupName}_snapshot.json"
    
    $snapshotData = @{
        GroupName = $ADGroup.Name
        GroupSID = $ADGroup.SID.Value
        Domain = $domain
        CapturedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Members = $Snapshot
    }
    
    $snapshotData | ConvertTo-Json -Depth 3 | Out-File $snapshotFile -Encoding UTF8
    Write-LogEntry "Snapshot saved: $snapshotFile" "DEBUG"
    
    return $snapshotFile
}

# Function to load previous snapshot
function Load-PreviousSnapshot {
    param(
        [object]$ADGroup,
        [string]$StoragePath
    )
    
    $domain = ($ADGroup.DistinguishedName -split ',DC=')[1]
    $safeGroupName = $ADGroup.Name -replace '[^a-zA-Z0-9]', '_'
    $snapshotFile = Join-Path $StoragePath "${domain}_${safeGroupName}_snapshot.json"
    
    if (Test-Path $snapshotFile) {
        try {
            $data = Get-Content $snapshotFile -Raw | ConvertFrom-Json
            Write-LogEntry "Previous snapshot loaded: $snapshotFile" "DEBUG"
            return $data.Members
        }
        catch {
            Write-LogEntry "Failed to load snapshot: $snapshotFile - $($_.Exception.Message)" "WARNING"
        }
    } else {
        Write-LogEntry "No previous snapshot found: $snapshotFile" "DEBUG"
    }
    
    return $null
}

# Function to create detailed HTML report
function New-ChangeReport {
    param(
        [string]$GroupName,
        [array]$Changes,
        [string]$ReportPath
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
    $safeGroupName = $GroupName -replace '[^a-zA-Z0-9]', '_'
    $reportFile = Join-Path $ReportPath "ChangeReport_${safeGroupName}_${reportDate}.html"
    
    $addedCount = ($Changes | Where-Object { $_.ChangeType -eq "MemberAdded" }).Count
    $removedCount = ($Changes | Where-Object { $_.ChangeType -eq "MemberRemoved" }).Count
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Group Changes Report - $GroupName</title>
    <meta charset="UTF-8">
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { 
            margin: 0; 
            font-size: 28px;
        }
        .header p { 
            margin: 5px 0 0 0; 
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .summary { 
            background: #e8f4fd; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 20px 0; 
            border-left: 5px solid #2196F3;
        }
        .change-added { 
            background: #d4edda; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }
        .change-removed { 
            background: #f8d7da; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px;
            border-left: 4px solid #dc3545;
        }
        .change-count {
            display: inline-block;
            background: #ff6b6b;
            color: white;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            text-align: center;
            line-height: 30px;
            margin-right: 10px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-added { color: #28a745; }
        .stat-removed { color: #dc3545; }
        .stat-total { color: #007bff; }
        .footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }
        .timestamp {
            background: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            margin: 15px 0;
            text-align: center;
            border-left: 4px solid #ffc107;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AD Sentinel Bot - Group Changes Report</h1>
            <p>Security Monitoring for Active Directory Groups</p>
        </div>
        
        <div class="content">
            <div class="timestamp">
                <strong>Report Generated:</strong> $(Get-Date -Format "dddd, MMMM dd, yyyy 'at' HH:mm:ss")<br>
                <strong>Monitoring Group:</strong> $GroupName
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div>Total Changes</div>
                    <div class="stat-number stat-total">$($Changes.Count)</div>
                    <div>Detected Modifications</div>
                </div>
                <div class="stat-card">
                    <div>Members Added</div>
                    <div class="stat-number stat-added">$addedCount</div>
                    <div>New Memberships</div>
                </div>
                <div class="stat-card">
                    <div>Members Removed</div>
                    <div class="stat-number stat-removed">$removedCount</div>
                    <div>Removed Memberships</div>
                </div>
            </div>
"@

    if ($Changes.Count -eq 0) {
        $htmlReport += @"
            <div class="summary">
                <h3>✅ No Changes Detected</h3>
                <p>No membership changes were detected in group <strong>$GroupName</strong> during this monitoring cycle.</p>
                <p>The group membership remains consistent with the previous snapshot.</p>
            </div>
"@
    } else {
        $htmlReport += @"
            <h3>🔍 Detailed Change Analysis</h3>
            <p>The following changes were detected in the group membership:</p>
"@

        $changeIndex = 1
        foreach ($change in $Changes) {
            $changeClass = if ($change.ChangeType -eq "MemberAdded") { "change-added" } else { "change-removed" }
            $icon = if ($change.ChangeType -eq "MemberAdded") { "➕" } else { "➖" }
            $changeTypeText = if ($change.ChangeType -eq "MemberAdded") { "Member Added" } else { "Member Removed" }
            
            $htmlReport += @"
            <div class="$changeClass">
                <div style="font-size: 1.2em; margin-bottom: 10px;">
                    <span class="change-count">$changeIndex</span>
                    <strong>$icon $changeTypeText</strong>
                </div>
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="width: 120px; padding: 5px; font-weight: bold;">Display Name:</td>
                        <td style="padding: 5px;">$($change.Member.DisplayName)</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; font-weight: bold;">Account Name:</td>
                        <td style="padding: 5px;">$($change.Member.SamAccountName)</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; font-weight: bold;">Object Type:</td>
                        <td style="padding: 5px;">$($change.Member.ObjectClass)</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; font-weight: bold;">Change Time:</td>
                        <td style="padding: 5px;">$($change.ChangeTime.ToString("yyyy-MM-dd HH:mm:ss"))</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px; font-weight: bold;">Distinguished Name:</td>
                        <td style="padding: 5px; font-size: 0.9em; color: #666;">$($change.Member.DistinguishedName)</td>
                    </tr>
                </table>
            </div>
"@
            $changeIndex++
        }
    }

    $htmlReport += @"
        </div>
        
        <div class="footer">
            <p><em>Generated by AD Sentinel Bot v$ScriptVersion | Enhanced Security Monitoring</em></p>
            <p style="font-size: 0.9em; margin-top: 5px;">
                This is an automated security report. Please review any detected changes for potential security implications.
            </p>
        </div>
    </div>
</body>
</html>
"@

    try {
        $htmlReport | Out-File $reportFile -Encoding UTF8
        Write-LogEntry "HTML report created: $reportFile" "SUCCESS"
        return $reportFile
    }
    catch {
        Write-LogEntry "Failed to create HTML report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# Function to send email notifications
function Send-ChangeNotification {
    param(
        [string]$GroupName,
        [array]$Changes,
        [string]$ReportFile
    )
    
    if (-not $EnableEmailNotifications) { 
        Write-LogEntry "Email notifications are disabled" "DEBUG"
        return 
    }
    
    # Validate email parameters
    if (-not $SMTPServer -or -not $EmailFrom -or -not $EmailTo) {
        Write-LogEntry "Email configuration incomplete. Check SMTPServer, EmailFrom, and EmailTo parameters." "WARNING"
        return
    }
    
    $addedCount = ($Changes | Where-Object { $_.ChangeType -eq "MemberAdded" }).Count
    $removedCount = ($Changes | Where-Object { $_.ChangeType -eq "MemberRemoved" }).Count
    
    $emailBody = @"
AD Sentinel Bot - Security Alert

Group: $GroupName
Monitoring Cycle: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

CHANGE SUMMARY:
===============
Total Changes Detected: $($Changes.Count)
• Members Added: $addedCount
• Members Removed: $removedCount

DETAILED CHANGES:
=================
$(
if ($Changes.Count -eq 0) {
    "No changes detected - group membership remains consistent."
} else {
    $changeDetails = ""
    foreach ($change in $Changes) {
        $icon = if ($change.ChangeType -eq "MemberAdded") { "➕" } else { "➖" }
        $changeDetails += "$icon $($change.ChangeType): $($change.Member.SamAccountName) ($($change.Member.DisplayName))`n"
    }
    $changeDetails
}
)

RECOMMENDED ACTIONS:
====================
1. Review the attached detailed HTML report
2. Verify the legitimacy of all changes
3. Investigate any unexpected modifications
4. Update security policies if necessary

TECHNICAL DETAILS:
==================
Script Version: $ScriptVersion
Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $env:USERDNSDOMAIN

This is an automated security notification from AD Sentinel Bot.
Please do not reply to this message.
"@

    try {
        Write-LogEntry "Sending email notification for $($Changes.Count) changes in group: $GroupName" "INFO"
        
        $mailParams = @{
            SmtpServer = $SMTPServer
            From = $EmailFrom
            To = $EmailTo
            Subject = "$EmailSubject - $GroupName ($($Changes.Count) changes)"
            Body = $emailBody
            ErrorAction = 'Stop'
        }
        
        if (Test-Path $ReportFile) {
            $mailParams.Attachments = $ReportFile
        }
        
        Send-MailMessage @mailParams
        
        Write-LogEntry "Email notification sent successfully to: $($EmailTo -join ', ')" "SUCCESS"
    }
    catch {
        Write-LogEntry "Failed to send email notification: $($_.Exception.Message)" "ERROR"
    }
}

try {
    Write-LogEntry "Initializing enhanced monitoring environment..." "INFO"

    $snapshotsPath = Join-Path $DataPath "Snapshots"
    $changesPath = Join-Path $DataPath "ChangeHistory"
    $reportsPath = Join-Path $DataPath "Reports"
    $logsPath = Join-Path $DataPath "Logs"
    $directories = @($DataPath, $snapshotsPath, $changesPath, $reportsPath, $logsPath)
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
                Write-LogEntry "Created directory: $dir" "INFO"
            }
            catch {
                Write-LogEntry "Failed to create directory $dir: $($_.Exception.Message)" "ERROR"
                exit 1
            }
        }
    }
    if (-not (Initialize-ADConnection -Timeout 30)) {
        Write-LogEntry "AD connection initialization failed. Stopping execution." "ERROR"
        exit 1
    }

    if (-not (Test-ADConnectivity -Timeout 15)) {
        Write-LogEntry "Active Directory connectivity test failed. Stopping execution." "ERROR"
        exit 1
    }
    $totalGroups = $GroupNames.Count
    $processedGroups = 0
    $changedGroups = 0

    foreach ($groupName in $GroupNames) {
        $processedGroups++
        Write-LogEntry "Processing group $processedGroups/$totalGroups: $groupName" "INFO"

        try {
            $resolvedGroup = Resolve-ADGroup -GroupIdentifier $groupName -ErrorAction Stop
            if (-not $resolvedGroup) {
                Write-LogEntry "Skipping unresolved group: $groupName" "WARNING"
                continue
            }
            try {
                $currentMembers = Get-GroupMembershipSnapshot -ADGroup $resolvedGroup -ErrorAction Stop
                Write-LogEntry "Current members in '$($resolvedGroup.Name)': $($currentMembers.Count)" "INFO"
            }
            catch {
                Write-LogEntry "Failed to get membership snapshot for group '$groupName': $($_.Exception.Message)" "ERROR"
                continue
            }
            $previousMembers = Load-PreviousSnapshot -ADGroup $resolvedGroup -StoragePath $snapshotsPath

            $hasChanges = $false
            if ($previousMembers) {
                $changes = Compare-GroupSnapshots -CurrentSnapshot $currentMembers -PreviousSnapshot $previousMembers

                if ($changes.Count -gt 0) {
                    $hasChanges = $true
                    $changedGroups++
                    Write-LogEntry "Changes detected in group '$($resolvedGroup.Name)': $($changes.Count)" "WARNING"
                    try {
                        $reportFile = New-ChangeReport -GroupName $resolvedGroup.Name -Changes $changes -ReportPath $reportsPath -ErrorAction Stop
                    }
                    catch {
                        Write-LogEntry "Failed to create change report for group '$($resolvedGroup.Name)'" "ERROR"
                        $reportFile = $null
                    }
                    if ($EnableEmailNotifications) {
                        try {
                            Send-ChangeNotification -GroupName $resolvedGroup.Name -Changes $changes -ReportFile $reportFile -ErrorAction Stop
                        }
                        catch {
                            Write-LogEntry "Failed to send email notification for group '$($resolvedGroup.Name)'" "ERROR"
                        }
                    }
                    foreach ($change in $changes) {
                        $icon = if ($change.ChangeType -eq "MemberAdded") { "➕" } else { "➖" }
                        Write-LogEntry "$icon $($change.ChangeType): $($change.Member.SamAccountName) ($($change.Member.DisplayName))" "INFO"
                    }
                    $changeRecord = @{
                        Group = $resolvedGroup.Name
                        GroupSID = $resolvedGroup.SID.Value
                        DetectedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Changes = $changes
                        ReportFile = if ($reportFile) { [System.IO.Path]::GetFileName($reportFile) } else { "N/A" }
                    }

                    $changeFile = Join-Path $changesPath "$($resolvedGroup.Name)_changes_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                    $changeRecord | ConvertTo-Json -Depth 4 | Out-File $changeFile -Encoding UTF8
                    Write-LogEntry "Change record saved: $changeFile" "INFO"
                }
                else {
                    Write-LogEntry "No changes detected in group: $($resolvedGroup.Name)" "SUCCESS"
                }
            }
            else {
                Write-LogEntry "Initial snapshot captured for group: $($resolvedGroup.Name)" "INFO"
            }
            try {
                $snapshotFile = Save-GroupSnapshot -ADGroup $resolvedGroup -Snapshot $currentMembers -StoragePath $snapshotsPath -ErrorAction Stop
                Write-LogEntry "Snapshot saved for next comparison: $snapshotFile" "DEBUG"
            }
            catch {
                Write-LogEntry "Failed to save snapshot for group '$($resolvedGroup.Name)'" "ERROR"
            }
        }
        catch {
            Write-LogEntry "Error processing group '$groupName': $($_.Exception.Message)" "ERROR"
            continue
        }
    }
    Write-LogEntry "Enhanced monitoring cycle completed successfully!" "SUCCESS"
    Write-LogEntry "Processed $processedGroups groups, $changedGroups had changes" "INFO"
    Write-LogEntry "Reports available in: $reportsPath" "INFO"
    Write-LogEntry "Logs available in: $logsPath" "INFO"
}
catch {
    Write-LogEntry "Monitoring failed: $($_.Exception.Message)" "ERROR"
    Write-LogEntry "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    exit 1
}
