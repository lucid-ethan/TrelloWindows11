#Requires -Version 5.1
[CmdletBinding()]
param ()

function Get-HardwareReadiness {
    $Result = @{
        Capable = $true
        Reason  = @()
    }

    # CPU Check
    try {
        $cpu = Get-CimInstance -Class Win32_Processor
        if ($cpu.AddressWidth -ne 64 -or $cpu.NumberOfLogicalProcessors -lt 2 -or $cpu.MaxClockSpeed -lt 1000) {
            $Result.Capable = $false
            $Result.Reason += "Processor"
        }
    } catch {
        $Result.Capable = $false
        $Result.Reason += "Processor (error)"
    }

    # RAM Check
    try {
        $mem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
        if (($mem / 1GB) -lt 4) {
            $Result.Capable = $false
            $Result.Reason += "Memory"
        }
    } catch {
        $Result.Capable = $false
        $Result.Reason += "Memory (error)"
    }

    # Disk Size Check
    try {
        $drive = Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty SystemDrive
        $size = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'" | Select-Object -ExpandProperty Size) / 1GB
        if ($size -lt 64) {
            $Result.Capable = $false
            $Result.Reason += "Storage"
        }
    } catch {
        $Result.Capable = $false
        $Result.Reason += "Storage (error)"
    }

    # TPM Check
    try {
        $tpm = Get-WmiObject -Namespace root\CIMV2\Security\MicrosoftTpm -Class Win32_Tpm
        $tpmVer = [int]$tpm.SpecVersion.Split(",")[0]
        if (-not $tpm.IsEnabled_InitialValue -or $tpmVer -lt 2) {
            $Result.Capable = $false
            $Result.Reason += "TPM"
        }
    } catch {
        $Result.Capable = $false
        $Result.Reason += "TPM (error)"
    }

    # Secure Boot Check
    try {
        if (-not (Confirm-SecureBootUEFI)) {
            $Result.Capable = $false
            $Result.Reason += "Secure Boot"
        }
    } catch {
        $Result.Capable = $false
        $Result.Reason += "Secure Boot (error)"
    }

    return $Result
}

# Run check
Write-Host "Running Windows 11 Compatibility Check..."
$check = Get-HardwareReadiness
$ResultString = if ($check.Capable) { "Capable" } else { "[Alert] Not Capable - $($check.Reason -join ', ')" }

# Trello
$TrelloAPIKey = "da5a4c36acf13b1f211692d77f390a08"
$TrelloToken  = "ATTA7c00d247b5749c4cf80e5c2d21dde358867c6a9422ce95afbf32062ae92fbbe4A4A0B13C"
$TrelloListID = "67f6d16211a4d25bf02eca9d"
$TrelloURL    = "https://api.trello.com/1/cards"
$computerName = $env:COMPUTERNAME

$body = @{
    key    = $TrelloAPIKey
    token  = $TrelloToken
    idList = $TrelloListID
    name   = $computerName
    desc   = $ResultString
}

try {
    Invoke-RestMethod -Uri $TrelloURL -Method Post -Body $body
    Write-Host "Posted to Trello: $ResultString"
    exit 0
} catch {
    Write-Host "[Error] Failed to post to Trello: $($_.Exception.Message)"
    exit 1
}
