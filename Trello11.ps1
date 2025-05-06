$compatibility = @()
$cpu = Get-CimInstance -ClassName Win32_Processor
$cpuName = $cpu.Name

# --- TPM Check ---
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
if ($tpm -and $tpm.SpecVersion -match "2\.0") {
    $compatibility += "TPM 2.0: ✅"
} else {
    $compatibility += "TPM 2.0: ❌"
}

# --- Secure Boot Check (Safe) ---
try {
    $secureBoot = Confirm-SecureBootUEFI
    if ($secureBoot) {
        $compatibility += "Secure Boot: ✅"
    } else {
        $compatibility += "Secure Boot: ❌"
    }
} catch {
    $compatibility += "Secure Boot: ❌ (Unsupported or BIOS)"
}

# --- CPU Compatibility Check ---
$intelCompatible = $cpuName -match "Intel\(R\).*Core\(TM\) i[3579]-[89][0-9]{2,}" -or $cpuName -match "Intel\(R\).*Core\(TM\) i[3579]-1[0-9]{3,}"
$amdCompatible = $cpuName -match "AMD Ryzen [3579] [23][0-9]{2,}" -and $cpuName -notmatch "2200G|2400G"

if ($intelCompatible -or $amdCompatible) {
    $compatibility += "CPU: ✅ ($cpuName)"
} else {
    $compatibility += "CPU: ❌ ($cpuName)"
}

# --- Summary ---
if ($compatibility -join "`n" -match "❌") {
    $result = "❌ Not Windows 11 Compatible"
} else {
    $result = "✅ Windows 11 Compatible"
}

Write-Host "`n$result`n"
$compatibility | ForEach-Object { Write-Host $_ }
