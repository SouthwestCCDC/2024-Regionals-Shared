Import-Module ActiveDirectory 

# this will break after you move these
. "$env:USERPROFILE\adImports\domDiscover.ps1"
. "$env:USERPROFILE\adImports\lclwinDiscover.ps1"
. "$env:USERPROFILE\adImports\propagate.ps1"
. "$env:USERPROFILE\adImports\tools.ps1"
. "$env:USERPROFILE\adImports\gpoScript.ps1"

function Harden {

    # this includes AD which is a DC
    $Windows_Comps = Get-ADComputer -Filter "OperatingSystem -like 'Windows*'"
    $all_ous = Get-ADOrganizationalUnit -Filter *
    $domain = Get-ADDomain

    # create seperate admin user for the domain
    $Username = "sys32admin"
    $Password = Read-Host -AsSecureString "Password for sys32admin: "
    $UserParams = @{
        SamAccountName = $Username
        Name = $Username
        DisplayName = $Username
        Enabled = $true
        AccountPassword = $Password
    }
    New-ADUser @UserParams
    Add-ADGroupMember -members $Username -Identity 'Domain Admins' 

    # this can be used in other sub scripts
    $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $Username, $Password

    domDiscover
    lclwinDiscover($Windows_Comps, $cred)

    Set-ADDefaultDomainPasswordPolicy -Credential $cred -Identity $domain.Name -LockoutDuration 01:00:00 `
    -LockoutObservationWindow 00:05:00 -ComplexityEnabled $True -ReversibleEncryptionEnabled $False -LockoutThreshold 5 -MinPasswordLength 15
    
    # $OU = $all_ous | Select-Object -ExpandProperty DistinguishedName
    # $target = $OU[$targetindex].ToString()
    #$target = $domain

    Write-Host "[i] Running WindowsHard.ps1 on all computers in the domain..." -ForegroundColor Yellow

    propagate($Windows_Comps, ".\winHard.ps1", $creds)

    Write-Host "[+] Finished deploying WindowsHard.ps1" -ForegroundColor Green

    #Write-Host "[i] Creating and linking GPO for the target" -ForegroundColor Yellow

    #gpoScript()

    #Write-Host "[+] Finished deploying the GP update" -ForegroundColor Green 

    Write-Host "[i] Reseting the krbtgt account password, a job will be created to perfom this automatically" -ForegroundColor Yellow

    if ("YES" -eq (Read-Host "Do you want to reset the krbtgt keys right now: ")) {
        for ($i = 0; $i -le 2; $i++) {
            Invoke-Expression (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/microsoft/New-KrbtgtKeys.ps1/master/New-KrbtgtKeys.ps1")
        }
    }

    Write-Host "[i] Forcing GPO update and logging all users on in the domain..." -ForegroundColor Yellow 

    Get-ADComputer -Filter * | ForEach-Object { Invoke-GPUpdate -Computer $_.name -Logoff -Boot -Force -RandomDelayInMinutes 0 }
    
    Write-Host "[i] Backing up GPO after hardening..." -ForegroundColor Yellow
    Backup-Gpo -All | Format-Table > "C:\Users\sys32admin\Tools\post_hard_gpo.txt"
    Write-Host "[+] GPO has been backed up to the specified folder" -ForegroundColor Green
    
    New-PSSession -Credential $creds -Name "switch"
    Invoke-Command -SessionName "switch" -ScriptBlock {
        $users = Get-ADUser -Identity 'Domain Admins'
        foreach ($user in $users) {
            if ($user.name -eq ('sys32admin' -or 'blackteam')) {
                continue;
            } else {
                Remove-ADGroupMember -Identity 'Domain Admins' -Members $user.name -Credential $creds
            }
        }
    }

    Get-PSSesion | Remove-PSSession

    # Invoke-Expression -Command "C:\'Program Files'\Malwarebytes\Anti-Malware\mb4uns.exe"
    installTools

    Write-Host "[i] Switch to sys32admin, change pwds, and move srcipts" -ForegroundColor Magenta
    
    # clear tracks
    Remove-Item -Path $(Get-PSReadlineOption).HistorySavePath -Force
}

function Main {

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

    Harden
}

Main
