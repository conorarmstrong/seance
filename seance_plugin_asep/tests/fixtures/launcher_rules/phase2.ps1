$sys = 'C:\Windows\System32'
$vbs = 'CreateObject("Scripting.FileSystemObject").OpenTextFile("C:\h249\hits.txt",8,True).WriteLine WScript.ScriptFullName'
$js  = 'new ActiveXObject("Scripting.FileSystemObject").OpenTextFile("C:\\h249\\hits.txt",8,true).WriteLine(WScript.ScriptFullName);'
$ps1 = 'Add-Content C:\h249\hits.txt $PSCommandPath'
foreach ($src in 'svc','tsk','dbg','run','ronce','hkcu','ui','lnk') {
  Set-Content "$sys\h249${src}vbs.vbs" $vbs -Encoding ascii
  Set-Content "$sys\h249${src}js.js" $js -Encoding ascii
  Set-Content "$sys\h249${src}ps1.ps1" $ps1 -Encoding ascii
}
$extra = 'vbs','js','ps1'
# Tasks: the extra extensions.
foreach ($v in $extra) {
  $n = "h249tsk$v"; Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute $n) -User SYSTEM -RunLevel Highest | Out-Null
  Start-ScheduledTask -TaskName $n
}
# Services and IFEO: vbs only (negative/positive control for PATHEXT beyond the four).
New-Service -Name h249svcvbs -BinaryPathName h249svcvbs -StartupType Manual | Out-Null; "SVC vbs: " + ((sc.exe start h249svcvbs) -join ' ' -replace '\s+',' ')
$all = 'com','exe','bat','cmd','all','vbs','js','ps1'
$run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$ronce = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
$hkcu = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
foreach ($v in $all) {
  New-ItemProperty -Force -Path $run -Name "h249run$v" -Value "h249run$v" | Out-Null
  New-ItemProperty -Force -Path $ronce -Name "h249ronce$v" -Value "h249ronce$v" | Out-Null
  New-ItemProperty -Force -Path $hkcu -Name "h249hkcu$v" -Value "h249hkcu$v" | Out-Null
}
# App Paths: a Run value naming only an App Paths key, no file of that name on the path.
Copy-Item "$sys\whoami.exe" C:\h249\apmarker.exe -Force
New-Item -Force 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\h249apx.exe' | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\h249apx.exe' -Name '(default)' -Value 'C:\h249\apmarker.exe'
New-ItemProperty -Force -Path $run -Name h249apx -Value h249apx | Out-Null
# The same App Paths name as a task and a service, for comparison.
Register-ScheduledTask -TaskName h249tskapx -Action (New-ScheduledTaskAction -Execute h249apx) -User SYSTEM -RunLevel Highest -Force | Out-Null; Start-ScheduledTask -TaskName h249tskapx
# Userinit: append the bare names.
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$ui = 'C:\WINDOWS\system32\userinit.exe,' + (($all | % { "h249ui$_" }) -join ',') + ','
Set-ItemProperty $wl -Name Userinit -Value $ui
(Get-ItemProperty $wl).Userinit
# Startup folder shortcuts with a bare target.
$sf = [Environment]::GetFolderPath('Startup'); $ws = New-Object -ComObject WScript.Shell
foreach ($v in $all) { $l = $ws.CreateShortcut("$sf\h249lnk$v.lnk"); $l.TargetPath = "h249lnk$v"; $l.Save(); "LNK $v stored TargetPath=[" + $ws.CreateShortcut("$sf\h249lnk$v.lnk").TargetPath + "]" }
# Autologon for the next boot.
Set-ItemProperty $wl -Name AutoAdminLogon -Value '1'; Set-ItemProperty $wl -Name DefaultUserName -Value 'analyst'; Set-ItemProperty $wl -Name DefaultPassword -Value 'Seance!2026'; Set-ItemProperty $wl -Name DefaultDomainName -Value '.'
Start-Sleep 5
foreach ($v in $extra + 'apx') { $i = Get-ScheduledTaskInfo -TaskName "h249tsk$v"; "TSK $v LastTaskResult=0x{0:X8}" -f $i.LastTaskResult }
