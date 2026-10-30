Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 3000 | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}; $x.Event.EventData.Data | % { $d[$_.Name] = $_.'#text' }
  if (($d.NewProcessName + ' ' + $d.CommandLine) -match 'h249') { '{0:HH:mm:ss} parent={1} new={2} cmd=[{3}]' -f $_.TimeCreated, $d.ParentProcessName, $d.NewProcessName, $d.CommandLine }
} | Sort-Object
'--- hits.txt'; Get-Content C:\h249\hits.txt -ErrorAction SilentlyContinue
