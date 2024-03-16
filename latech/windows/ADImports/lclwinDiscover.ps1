Import-Module ScheduledTasks
Import-Module NetTCPIP

function lclwinDiscover {
    param (
        $windows_comps,
        [pscredential]$creds
    )

    $discoverypath = "$env:USERPROFILE\tools\discovery"


    Write-Host "[+] Running discovery dump..." -ForegroundColor Green
    Write-Host "[i] YOU SHOULD STILL BE USING THE OTHER TOOLS THAT WERE INSTALLED" -ForegroundColor Yellow
    if (Test-Path -Path "$discoverypath") {
        continue
    }else{
        New-Item -Path "$env:USERPROFILE" -Name discovery -type Directory
    }


    foreach ($comp in $windows_comps) {
        $outs = Invoke-Command -ComputerName $comp.Name -Credential $creds -ScriptBlock {

            Write-Host "[+] Gathering services..." -ForegroundColor Yellow
            Get-Service -Verbose | Format-Table -AutoSize

            $owners = @{}
            Get-WmiObject win32_process | Foreach-Object {$owners[$_.handle] = $_.getowner().user} -ErrorAction SilentlyContinue
            Get-Process | Select-Object processname,Id,@{l="Owner";e={$owners[$_.id.tostring()]}} -ErrorAction SilentlyContinue | Format-Table -AutoSize > "$discoverypath\processes.txt"

            Get-NetTCPConnection -Verbose | Format-Table -AutoSize

            Get-ScheduledTask -Verbose | Format-Table -AutoSize

            Get-CimInstance Win32_StartupCommand | `
            Select-Object Name, command, Location, User | `
            Format-Table -AutoSize 

            Get-ADGroupMember | Format-Table -AutoSize 
            Get-LocalUser | Format-Table -AutoSize 

            Write-Host "[+] Data dumped to 'Discovery' folder on your desktop" -ForegroundColor Green

            Write-Host "[i] You should still be using other tools because this won't catch everything" -ForegroundColor Yellow

        }

        $outs | Out-File -FilePath "$discoverypath\$($(comp).Name).txt"
    }

}
