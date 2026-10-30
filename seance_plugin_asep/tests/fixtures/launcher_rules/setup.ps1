# HUNT-249: plant candidate files for bare program names, one set per launcher and variant.
$ErrorActionPreference = 'Stop'
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
New-ItemProperty -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord -ErrorAction SilentlyContinue | Out-Null
if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit')) { New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' | Out-Null; New-ItemProperty -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -PropertyType DWord | Out-Null }
New-Item -ItemType Directory -Force C:\h249 | Out-Null
$sys = 'C:\Windows\System32'
$marker = "$sys\whoami.exe"
$bat = "@echo %~f0 %* >> C:\h249\hits.txt`r`n"
foreach ($src in 'svc','tsk','dbg','run','ronce','hkcu','ui','lnk','ap') {
  foreach ($v in 'com','exe','bat','cmd','all') {
    $n = "h249$src$v"
    $exts = if ($v -eq 'all') { 'com','exe','bat','cmd' } else { ,$v }
    foreach ($e in $exts) {
      $p = "$sys\$n.$e"
      if ($e -in 'com','exe') { Copy-Item $marker $p -Force } else { Set-Content -Path $p -Value $bat -NoNewline -Encoding ascii }
    }
  }
}
Get-ChildItem "$sys\h249*" | Measure-Object | % Count
