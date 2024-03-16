Import-Module ActiveDirectory

function propogate {
    param (
        $Windows_Comps
        [String]$filepath,
        [PSCredential]$cred
    )

    Write-Host "[i] Running $path on all windows computers in the domain..." -ForegroundColor Yellow

    Invoke-Command -ComputerName $Windows_Comps.Name -Credential $cred -Authentication Kerberos -FilePath $filepath -ErrorAction Continue

    $prompt = Read-Host -prompt "would you like to change pwsh to block scripts (y) (n)"
    if ($prompt -eq "y") {
        Invoke-Command -ComputerName $Windows_Comps.Name -Credential $cred -Authentication Kerberos -ScriptBlock {
                Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -ErrorAction Continue
            }
    }

    Write-Host "[+] Finished deploying $filepath" -ForegroundColor Green
}
