if ( !(Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue) ) 
{
    Write-Error "Couldn't find the Microsoft-Windows-Sysmon/Operational event channel on your host. Install sysmon from live.sysinternals.com and try again."
    exit
}

Write-Host -Foreground Blue 'Sysmon Event Parser'
Write-Host -Foreground Blue "Version 0.0.1"