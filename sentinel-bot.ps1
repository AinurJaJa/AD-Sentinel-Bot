<#
.SYNOPSIS
    AD Sentinel Bot - Core Monitoring Framework
.DESCRIPTION
    Core functionality for monitoring Active Directory group memberships.
    This version includes group discovery, membership tracking, and change detection.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$GroupNames,
    
    [string]$DataPath = "C:\ADSentinelBot\Data",
    
    [switch]$UseLegacyADSNAPIN
)

# Core configuration
$ScriptVersion = "1.0.0"
$ScriptName = "AD Sentinel Bot"

Write-Host "🛡️ $ScriptName v$ScriptVersion - Starting Core Monitoring" -ForegroundColor Cyan

# Function to initialize AD connection
function Initialize-ADConnection {
    if ($UseLegacyADSNAPIN) {
        Write-Verbose "Using legacy Quest Active Directory Snapin"
        if (-not (Get-PSSnapin -Name Quest.ActiveRoles.ADManagement -ErrorAction SilentlyContinue)) {
            Add-PSSnapin Quest.ActiveRoles.ADManagement
        }
    } else {
        Write-Verbose "Using Microsoft ActiveDirectory module"
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}

# Function to resolve group identity
function Resolve-ADGroup {
    param([string]$GroupIdentifier)
    
    try {
        if ($UseLegacyADSNAPIN) {
            return Get-QADGroup -Identity $GroupIdentifier -ErrorAction Stop
        } else {
            return Get-ADGroup -Identity $GroupIdentifier -Properties DistinguishedName, SID -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "Cannot resolve group: $GroupIdentifier - $($_.Exception.Message)"
        return $null
    }
}

# Function to capture group membership snapshot
function Get-GroupMembershipSnapshot {
    param([object]$ADGroup)
    
    $members = @()
    
    try {
        if ($UseLegacyADSNAPIN) {
            $rawMembers = Get-QADGroupMember -Identity $ADGroup.DistinguishedName -ErrorAction Stop
        } else {
            $rawMembers = Get-ADGroupMember -Identity $ADGroup.DistinguishedName -ErrorAction Stop
        }
        
        foreach ($member in $rawMembers) {
            $members += [PSCustomObject]@{
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
        }
    }
    catch {
        Write-Verbose "Group appears to be empty or inaccessible: $($ADGroup.Name)"
    }
    
    # Handle empty groups
    if ($members.Count -eq 0) {
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
    
    # Convert to lookup tables for easier comparison
    $currentLookup = @{}
    $previousLookup = @{}
    
    $CurrentSnapshot | ForEach-Object { $currentLookup[$_.DistinguishedName] = $_ }
    $PreviousSnapshot | ForEach-Object { $previousLookup[$_.DistinguishedName] = $_ }
    
    # Detect new members (in current but not in previous)
    foreach ($dn in $currentLookup.Keys) {
        if (-not $previousLookup.ContainsKey($dn)) {
            $detectedChanges += [PSCustomObject]@{
                ChangeType = "MemberAdded"
                Member = $currentLookup[$dn]
                ChangeTime = Get-Date
                ChangeDescription = "User/Group added to group"
            }
        }
    }
    
    # Detect removed members (in previous but not in current)
    foreach ($dn in $previousLookup.Keys) {
        if (-not $currentLookup.ContainsKey($dn)) {
            $detectedChanges += [PSCustomObject]@{
                ChangeType = "MemberRemoved"
                Member = $previousLookup[$dn]
                ChangeTime = Get-Date
                ChangeDescription = "User/Group removed from group"
            }
        }
    }
    
    # Handle empty group transitions
    $wasEmpty = $PreviousSnapshot[0].SamAccountName -eq "EMPTY_GROUP_PLACEHOLDER"
    $isEmpty = $CurrentSnapshot[0].SamAccountName -eq "EMPTY_GROUP_PLACEHOLDER"
    
    if ($wasEmpty -and -not $isEmpty) {
        Write-Verbose "Group transitioned from empty to having members"
    }
    elseif (-not $wasEmpty -and $isEmpty) {
        Write-Verbose "Group transitioned from having members to empty"
    }
    
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
    Write-Verbose "Snapshot saved: $snapshotFile"
    
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
            Write-Verbose "Previous snapshot loaded: $snapshotFile"
            return $data.Members
        }
        catch {
            Write-Warning "Failed to load snapshot: $snapshotFile"
        }
    }
    
    return $null
}

# Main execution flow
try {
    # Initialize environment
    Write-Host "Initializing monitoring environment..." -ForegroundColor Yellow
    
    $snapshotsPath = Join-Path $DataPath "Snapshots"
    $changesPath = Join-Path $DataPath "ChangeHistory"
    
    # Create required directories
    @($DataPath, $snapshotsPath, $changesPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Verbose "Created directory: $_"
        }
    }
    
    # Initialize AD connection
    Initialize-ADConnection
    
    # Process each target group
    foreach ($groupName in $GroupNames) {
        Write-Host "`n🔍 Monitoring group: $groupName" -ForegroundColor White
        
        $resolvedGroup = Resolve-ADGroup -GroupIdentifier $groupName
        if (-not $resolvedGroup) {
            Write-Warning "Skipping unresolved group: $groupName"
            continue
        }
        
        # Capture current state
        $currentMembers = Get-GroupMembershipSnapshot -ADGroup $resolvedGroup
        Write-Host "   Current members: $($currentMembers.Count)" -ForegroundColor Gray
        
        # Load previous state
        $previousMembers = Load-PreviousSnapshot -ADGroup $resolvedGroup -StoragePath $snapshotsPath
        
        if ($previousMembers) {
            # Compare and detect changes
            $changes = Compare-GroupSnapshots -CurrentSnapshot $currentMembers -PreviousSnapshot $previousMembers
            
            if ($changes.Count -gt 0) {
                Write-Host "   ⚠️  Changes detected: $($changes.Count)" -ForegroundColor Red
                foreach ($change in $changes) {
                    $icon = if ($change.ChangeType -eq "MemberAdded") { "➕" } else { "➖" }
                    Write-Host "      $icon $($change.ChangeType): $($change.Member.SamAccountName)" -ForegroundColor Yellow
                }
                
                # Save change record
                $changeRecord = @{
                    Group = $resolvedGroup.Name
                    GroupSID = $resolvedGroup.SID.Value
                    DetectedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Changes = $changes
                }
                
                $changeFile = Join-Path $changesPath "$($resolvedGroup.Name)_changes_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $changeRecord | ConvertTo-Json -Depth 4 | Out-File $changeFile -Encoding UTF8
                Write-Verbose "Change record saved: $changeFile"
                
            } else {
                Write-Host "   ✅ No changes detected" -ForegroundColor Green
            }
        } else {
            Write-Host "   📝 Initial snapshot captured" -ForegroundColor Blue
        }
        
        # Save current snapshot for next comparison
        Save-GroupSnapshot -ADGroup $resolvedGroup -Snapshot $currentMembers -StoragePath $snapshotsPath
    }
    
    Write-Host "`n🎉 Monitoring cycle completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Monitoring failed: $($_.Exception.Message)"
    exit 1
}