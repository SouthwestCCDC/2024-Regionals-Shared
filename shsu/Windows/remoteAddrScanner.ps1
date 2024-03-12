$logFilePath = "C:\Users\ProcessLog.txt"
$remoteAddressPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

function Get-ProcessWithRemoteAddress {
    Get-Process | Where-Object { $_.Id -ne $PID } | ForEach-Object {
        $remoteAddresses = Get-NetTCPConnection -OwningProcess $_.Id -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -match $remoteAddressPattern } |
            Select-Object -ExpandProperty RemoteAddress |
            ForEach-Object { $_.Split(":")[0] } |
            Select-Object -Unique
        if ($remoteAddresses) {
            $_ | Add-Member -NotePropertyName RemoteAddresses -NotePropertyValue $remoteAddresses
            $_
        }
    }
}

function Log-ProcessInfo {
    Param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$process
    )
    $processPath = (Get-Process -Id $process.Id).Path
    $logMessage = @"
[$(Get-Date)] Process '$($process.ProcessName)' (ID $($process.Id), Path $processPath) started with remote addresses: $($process.RemoteAddresses -join ', ')
"@
    Add-Content $logFilePath $logMessage
}

function Stop-ProcessWithPrompt {
    Param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$process
    )
    
    $processName = $process.ProcessName
    $executablePath = (Get-Process -Id $process.Id).Path
    
    $stopProcess = Read-Host "A new process '$processName' with remote addresses $($process.RemoteAddresses -join ', ') has been detected. Do you want to stop it? (Y/N)"
    if ($stopProcess -eq "Y" -or $stopProcess -eq "y") {
        Get-Process | Where-Object {$_.ProcessName -eq $processName -and $_.Path -eq $executablePath} | Stop-Process -Force
    }
}

$prevProcesses = Get-ProcessWithRemoteAddress

while ($true) {
    
    $currProcesses = Get-ProcessWithRemoteAddress
    $newProcesses = Compare-Object -ReferenceObject $prevProcesses -DifferenceObject $currProcesses -Property Id -PassThru
    foreach ($newProcess in $newProcesses) {
        $processPath = (Get-Process -Id $newProcess.Id).Path
        $alertMessage = "A new process $($newProcess.ProcessName) (ID $($newProcess.Id), Path $processPath) with remote addresses $($newProcess.RemoteAddresses -join ', ') has been detected."
        Write-Host $alertMessage
        [console]::beep(2000,500)
        Log-ProcessInfo -process $newProcess
        Stop-ProcessWithPrompt -process $newProcess
    }
    $prevProcesses = $currProcesses
}
