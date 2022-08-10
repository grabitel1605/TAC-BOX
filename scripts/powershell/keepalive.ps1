echo "
 +-+-+-+-+ +-+-+-+-+-+-+
 |K|e|e|p| |A|l|i|v|e|!|
 +-+-+-+-+ +-+-+-+-+-+-+"
$WShell = New-Object -com "Wscript.shell"

while ($True)

{
$Wshell.sendkeys("{SCROLLLOCK}")
Start-Sleep -Milliseconds 100
$Wshell.sendkeys("{SCROLLLOCK}")
Start-Sleep -Seconds 240
}