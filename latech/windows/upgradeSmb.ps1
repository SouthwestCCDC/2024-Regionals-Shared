
function Upgrade2SMBv2 {

    $Parameters = @{
        RequireSecuritySignature = $true
        EnableSecuritySignature = $true
        EncryptData = $true
        Confirm = $false
        EnableSMB1Protocol = $false
        EnableSMB2Protocol = $true
    }
    Set-SmbServerConfiguration @Parameters

    Disable-WindowsOptionalFeature -Online -FeatureName -Remove SMB1Protocol
}

function Upgrade2SMBv3 {

    $Parameters = @{
        RequireSecuritySignature = $true
        EnableSecuritySignature = $true
        EncryptData = $true
        Confirm = $false
        EnableSMB1Protocol = $false
        EnableSMB2Protocol = $true
    }
    Set-SmbServerConfiguration @Parameters

}

function Main {

    Write-Host "Upgrade2SMBv2"
    Write-Host "Upgrade2SMBv3"

    $x = Read-Host -prompt "option"
    switch ($x) {
        "v2" { Upgrade2SMBv2 }
        "v3" { Upgrade2SMBv3 }
        Default { return }
    }
}
