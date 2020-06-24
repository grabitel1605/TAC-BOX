Get-Service | WHERE {$_.status -eq "Running"} | SELECT displayname,status | Out-File .\running_procs.txt
