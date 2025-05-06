# --- Compatibility Checks ---
$compatibility = @()
$cpu = Get-CimInstance -ClassName Win32_Processor
$cpuName = $cpu.Name

# TPM check
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
if ($tpm -and $tpm.SpecVersion -match "2\.0") {
    $compatibility += "TPM 2.0: Present"
} else {
    $compatibility += "TPM 2.0: Not Present"
}

# Secure Boot check
try {
    $secureBoot = Confirm-SecureBootUEFI
    if ($secureBoot) {
        $compatibility += "Secure Boot: Enabled"
    } else {
        $compatibility += "Secure Boot: Disabled"
    }
} catch {
    $compatibility += "Secure Boot: Not Supported"
}

# CPU check
$intelCompatible = $cpuName -match "Intel\(R\).*Core\(TM\) i[3579]-[89][0-9]{2,}" -or $cpuName -match "Intel\(R\).*Core\(TM\) i[3579]-1[0-9]{3,}"
$amdCompatible = $cpuName -match "AMD Ryzen [3579] [23][0-9]{2,}" -and $cpuName -notmatch "2200G|2400G"

if ($intelCompatible -or $amdCompatible) {
    $compatibility += "CPU: Compatible ($cpuName)"
} else {
    $compatibility += "CPU: Not Compatible ($cpuName)"
}

# Final result
if ($compatibility -join "`n" -match "Not") {
    $result = "System is NOT Windows 11 Compatible"
} else {
    $result = "System IS Windows 11 Compatible"
}

# --- Output ---
Write-Host "`n$result`n"
$compatibility | ForEach-Object { Write-Host $_ }

# --- Push to Trello ---
$TrelloAPIKey = "da5a4c36acf13b1f211692d77f390a08"
$TrelloToken = "ATTA7c00d247b5749c4cf80e5c2d21dde358867c6a9422ce95afbf32062ae92fbbe4A4A0B13C"
$TrelloListID = "67f6d16211a4d25bf02eca9d"
$TrelloURL = "https://api.trello.com/1/cards"
$computerName = $env:COMPUTERNAME

$body = @{
    key    = $TrelloAPIKey
    token  = $TrelloToken
    idList = $TrelloListID
    name   = "$computerName - Win11 Compatibility"
    desc   = "$result`n`n" + ($compatibility -join "`n")
}

Invoke-RestMethod -Uri $TrelloURL -Method Post -Body $body
Write-Host "`nTrello card created."
