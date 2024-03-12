Import-Module ActiveDirectory

function BlkPasswd { 
    
    Write-Host "[+] Changing all of the passwords and writing them to a csv..." -ForegroundColor Green
    # build the character array for generating the passwords
    $alph = foreach($i in 49..126) {[char]$i}

    $domainusers = Get-ADUser -Filter *

    # generate the users new passwords and save them to a csv file
    foreach($user in $domainusers) {

        if ($user.SamAccountName -eq 'blackteam') {
            Write-Host "nah"
            continue
        }
        if ($user.SamAccountName -eq 'sys32admin') {
            Write-Host "nah"
            continue
        }

        for($i = 0; $i -lt 14; $i++) { $pass += $alph | Get-Random }
        ConvertTo-SecureString -AsPlainText '$pass';
        Set-ADAccountPassword -Identity $user.SamAccountName -Reset -NewPassword '$pass'; 
        
        PrintErr(!$?,"Error in changing the password for $user, make sure you have right privs")
        $temp = $user.SamAccountName;

        $PasswordProgress = @{
                Activity         = 'Changing Password'
                PercentComplete  = ($user / ($domainusers.Length-2)) * 100
                Status           = 'Progress'
                CurrentOperation = "$user"
        }

        Write-Progress @PasswordProgress
        Write-Output "$temp,$pass" >> $env:USERPROFILE\Desktop\export.csv
    }

    Write-Host "[+] Bulk password change is complete and csv file is located on your desktop" -ForegroundColor Green
}
