$sys='C:\Windows\System32'; $bat = "@echo %~f0 %* >> C:\h249\hits.txt`r`n"
$vbs = 'CreateObject("Scripting.FileSystemObject").OpenTextFile("C:\h249\hits.txt",8,True).WriteLine WScript.ScriptFullName'
$ws = New-Object -ComObject WScript.Shell
foreach ($src in 'run','tsk') {
  Copy-Item "$sys\whoami.exe" "$sys\h249${src}pif.pif" -Force
  $l = $ws.CreateShortcut("$sys\h249${src}lnk.lnk"); $l.TargetPath = "$sys\whoami.exe"; $l.Save()
  Copy-Item "$sys\whoami.exe" "$sys\h249${src}exebat.exe" -Force; Set-Content "$sys\h249${src}exebat.bat" $bat -NoNewline -Encoding ascii
  Set-Content "$sys\h249${src}batcmd.bat" $bat -NoNewline -Encoding ascii; Set-Content "$sys\h249${src}batcmd.cmd" $bat -NoNewline -Encoding ascii
  Copy-Item "$sys\whoami.exe" "$sys\h249${src}exevbs.exe" -Force; Set-Content "$sys\h249${src}exevbs.vbs" $vbs -Encoding ascii
  Copy-Item "$sys\whoami.exe" "$sys\h249${src}exemsc.exe" -Force
}
$run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty $run | Get-Member -MemberType NoteProperty | ? Name -like 'h249*' | % { Remove-ItemProperty $run -Name $_.Name }
foreach ($v in 'pif','lnk','exebat','batcmd','exevbs','none') {
  New-ItemProperty -Force -Path $run -Name "h249run$v" -Value "h249run$v" | Out-Null
  $n = "h249tsk$v"; Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute $n) -User SYSTEM -RunLevel Highest -Force | Out-Null; Start-ScheduledTask -TaskName $n
}
Start-Sleep 6
foreach ($v in 'pif','lnk','exebat','batcmd','exevbs','none') { $i = Get-ScheduledTaskInfo -TaskName "h249tsk$v"; "TSK $v LastTaskResult=0x{0:X8}" -f $i.LastTaskResult }
