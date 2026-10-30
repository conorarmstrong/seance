$vs = 'com','exe','bat','cmd','all'
# 1. Services: ImagePath is the bare name exactly.
foreach ($v in $vs) {
  $n = "h249svc$v"
  sc.exe delete $n 2>$null | Out-Null
  New-Service -Name $n -BinaryPathName $n -StartupType Manual | Out-Null
  $ip = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$n").ImagePath
  $r = (sc.exe start $n) -join ' '
  "SVC $v ImagePath=[$ip] start=> $($r -replace '\s+',' ')"
}
# 2. Scheduled tasks: Exec Command is the bare name, run as SYSTEM.
foreach ($v in $vs) {
  $n = "h249tsk$v"
  Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $n
  Register-ScheduledTask -TaskName $n -Action $a -User 'SYSTEM' -RunLevel Highest | Out-Null
  Start-ScheduledTask -TaskName $n
}
Start-Sleep 8
foreach ($v in $vs) { $i = Get-ScheduledTaskInfo -TaskName "h249tsk$v"; "TSK $v LastTaskResult=0x{0:X8}" -f $i.LastTaskResult }
# 3. IFEO Debugger: bare name, target launched through CreateProcess (UseShellExecute=false).
foreach ($v in $vs) {
  $t = "h249tgt$v.exe"
  Copy-Item C:\Windows\System32\whoami.exe "C:\Windows\System32\$t" -Force
  $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$t"
  New-Item -Force $k | Out-Null
  New-ItemProperty -Force -Path $k -Name Debugger -Value "h249dbg$v" | Out-Null
  $psi = New-Object System.Diagnostics.ProcessStartInfo "C:\Windows\System32\$t"
  $psi.UseShellExecute = $false
  try { $p = [Diagnostics.Process]::Start($psi); $p.WaitForExit(5000) | Out-Null; "DBG $v CreateProcess ok pid=$($p.Id) exit=$($p.ExitCode)" } catch { "DBG $v CreateProcess error: $($_.Exception.InnerException.Message) $($_.Exception.Message)" }
}
Start-Sleep 35
foreach ($v in $vs) { "SVC $v state: " + ((sc.exe query "h249svc$v" | Select-String 'STATE|WIN32_EXIT') -join ' ' -replace '\s+',' ') }
