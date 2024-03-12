Import-Module ExchangePowerShell

# perform tasks to harden Exchange
function Main {
    param (
        $mode
    )

    # should stop underprivledged users from running the script
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)

    if ($p.IsInRole("Domain Admins")) { 
        Write-Host "Welcome to WindowsHard!" -ForegroundColor Green
        Write-Host "Goodluck Today!!!" -ForegroundColor Green
    }else{ 
        Write-Host "No Red Team Allowed!!!" -ForegroundColor Red
        Write-Host "Hope You Have a Good Day!!!" -ForegroundColor Red
        exit
    }

    $hardenExch = $(Write-Host "[?] Do you want to Harden Exchange (y): " -ForegroundColor Magenta -NoNewline; Read-Host)
    if ($hardenExch -eq ("y")) {
        if (Get-Service | Select-Object -Property "Name" | Select-String -Pattern "Exchange") {
            ExchangeHard($mode)
        }
    }

    if ($mode = "undo") {
    }

    if ($mode = "undo") {
    }
}

Main
