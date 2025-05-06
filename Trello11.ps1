# Check if running as administrator, if not, re-launch as admin
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as Administrator, restarting with elevated permissions..."
    $arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell -ArgumentList $arguments -Verb RunAs
    exit
}

$computerName = $env:COMPUTERNAME
$compatibility = @()

# TPM check
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
if ($tpm -and $tpm.SpecVersion -match "2\.0") {
    $compatibility += "TPM 2.0: ✅"
} else {
    $compatibility += "TPM 2.0: ❌"
}

# Secure Boot check
$secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
if ($secureBoot -eq $true) {
    $compatibility += "Secure Boot: ✅"
} else {
    $compatibility += "Secure Boot: ❌"
}

# CPU generation check (>= 8th gen Intel or Ryzen 2nd gen)
$cpu = Get-CimInstance -ClassName Win32_Processor
$cpuName = $cpu.Name
if ($cpuName -match "Intel\(R\).*Core\(TM\) i[5-9]-8") {
    $compatibility += "CPU: ✅ ($cpuName)"
} elseif ($cpuName -match "AMD Ryzen 5 2|AMD Ryzen 7 2") {
    $compatibility += "CPU: ✅ ($cpuName)"
} else {
    $compatibility += "CPU: ❌ ($cpuName)"
}

# Final result
if ($compatibility -join "`n" -match "❌") {
    $result = "❌ Not Windows 11 Compatible"
} else {
    $result = "✅ Windows 11 Compatible"
}

# Post to Trello
$TrelloAPIKey = "da5a4c36acf13b1f211692d77f390a08"
$TrelloToken = "ATTA7c00d247b5749c4cf80e5c2d21dde358867c6a9422ce95afbf32062ae92fbbe4A4A0B13C"
$TrelloListID = "67f6d16211a4d25bf02eca9d"
$TrelloURL = "https://api.trello.com/1/cards"

$body = @{
    key    = $TrelloAPIKey
    token  = $TrelloToken
    idList = $TrelloListID
    name   = "$computerName - Windows 11 Compatibility"
    desc   = "$result`n`n" + ($compatibility -join "`n")
}

Invoke-RestMethod -Uri $TrelloURL -Method Post -Body $body
Write-Host "Trello card posted with Windows 11 compatibility info."
