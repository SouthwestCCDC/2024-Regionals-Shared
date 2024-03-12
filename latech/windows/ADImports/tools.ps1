enum Tools{  
    TCPView
    Procmon
    Autoruns
}

function installTools {

    Write-Host "[+] Installing tools..."

    
    $urls = @(
        [Tools]::TCPView = "https://download.sysinternals.com/files/TCPView.zip"
        [Tools]::Procmon = "https://download.sysinternals.com/files/ProcessMonitor.zip"
        [Tools]::Autoruns = "https://download.sysinternals.com/files/Autoruns.zip"
    )

    $zipPath = @(
        [Tools]::TCPView  = "$env:USERPROFILE\Desktop\Tools\TCPView.zip"
        [Tools]::Procmon  = "$env:USERPROFILE\Desktop\Tools\ProcessMonitor.zip"
        [Tools]::Autoruns = "$env:USERPROFILE\Desktop\Tools\Autoruns.zip"
    )

    foreach ($tool in [Tools].GetEnumValues()) {
        (New-Object New.WebClient).DownloadFile($urls[$tool].ToString(), "$env:USERPROFILE\Desktop\Tools\$tool.zip")

        Expand-Archive -LiteralPath $zipPath[$tool].ToString() -DestinationPath "$env:USERPROFILE\Desktop\Tools\$tool"
    }   
    
    Write-Host "[+] Finished installing tools" -ForegroundColor Green
}

