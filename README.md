# AD Sentinel Bot - Core Monitoring

Basic PowerShell framework for monitoring Active Directory group membership changes.

## Features
- AD group discovery and resolution
- Membership snapshot capture
- Change detection between scans
- JSON-based data storage

## Usage
.\ADSentinelBot.ps1 -GroupNames "Domain Admins", "Enterprise Admins"

Data Structure

C:\ADSentinelBot\Data\
├── Snapshots\          # Group membership JSON snapshots
└── ChangeHistory\      # Detected change records
Supported Environments
Windows PowerShell 5.0+

Active Directory module or Quest Snapin