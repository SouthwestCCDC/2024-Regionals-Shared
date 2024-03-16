function domDiscover {

    New-Item -Type Directory -Name tools | Get-Item -Force | ForEach-Object {$_.Attributes = $_.Attributes -bor "Hidden"} 

    # backup the gpo and users before hardening
    Backup-Gpo -All -Path "C:\Users\sys32admin\tools\backup.txt"
    Get-ADUser -Filter * | Select-Object -ExpandProperty name, DistinguishedName, Enabled | Format-Table -AutoSize >> "C:\Users\sys32admin\tools\domain_users.txt"
    Get-ADOrganizationlUnits -Filter * | Select-Object -ExpandProperty Name, DistinguishedName, LinkedGroupPolicyObjects | Format-Table -AutoSize >> "C:\Users\sys32admin\tools\ous.txt"
    Get-ADDefaultDomainPasswordPolicy -All -Path "C:\Users\sys32admin\tools\pass_backup.txt"
    Get-NetTcpConncetions -State Listen -Verbose | Format-Table -autosize >> "env:Userprofile\tools\ports.txt"

}
