Import-Module ActiveDirectory
Import-Module GroupPolicy

$Keypaths = @{
    HKLM_Policies   = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\"
    Install_Policies= "HKLM\Software\Policies\Microsoft\Windows\"
    LSA             = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\"
    LanmanServer    = "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\"
    HKCU_Policies   = "HKCU\Software\Policies\Microsoft\Windows\System"

}

enum Keypaths {
    HKLM_Policies
    Win_Components
    LSA
    LanmanServer
}

class GPO {

    [string]$gpoName
    [string]$gpoPath
    [string]$gpoValue
    [int]$type
    [int]$value
    [string]$target


    GPO() { $this.Init(@{}) }

    GPO([hashtable]$Properties) { $this.Init($Properties) }


    [void] Init([hashtable]$Properties) {
        foreach ($Property in $Properties.Keys) {
            $this.$Property = $Properties.$Property
        }
    }

    [string] ToString() {
        return "$($this.gpoName) by $($this.gpoPath) $($this.gpoValue) $($this.type) $($this.value)"
    }



    [void] CreateGPO() {
        New-GPO -Name $this.gpoName
        Set-GPRegistryValue -Name $this.gpoName -Key $this.gpoPath -ValueName $this.gpoValue -Type $this.type -Value $this.value
        New-GPLink -Name $this.gpoName $this.target
    }
}

function gpoScript {

    [GPO]::new(@{gpoName = "DisableRSA"; gpoPath = "$Keypaths.HKLM_Policies + Windows Remote Shell\Allow Remote Shell Access"; gpoValue = "State"; type = "DWord"; value = 0; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "PreventRegistryEditingGPO"; gpoPath = "$Keypaths.HKLM_Policies + System"; gpoValue = "DisableRegistryTools"; type = "DWord"; value = 1; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "DoNotStoreLMHash"; gpoPath = "$Keypaths.LSA"; gpoValue ="NoLMHash"; type = "DWord"; value = 1; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "DisallowAnonymousSIDTranslationGPO"; gpoPath = "$Keypaths.LSA"; gpoValue = "LSAAnonymousName"; type = "DWord"; value = 0; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "DisableAnonymousPermissionsGPO"; gpoPath = "$Keypaths.LSA"; gpoValue = "EveryoneIncludesAnonymous"; type = "DWord"; value = 0; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "RestrictAnonymousSAMGPO"; gpoPath = "$Keypaths.LanmanServer"; gpoValue = "RestrictAnonymousSAM"; type = "DWord"; value = 1; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "RestrictAnonymousAccessGPO"; gpoPath = "$Keypaths.LanmanServer"; gpoValue = "RestrictNullSessAccess"; type = "DWord"; value = 1; target = $target}).CreateGPO()
    [GPO]::new(@{gpoName = "PreventCMD"; gpoPath = "$Keypaths.HKCU_Policies"; gpoValue = "DisableCMD"; type = "DWord"; value = 2; target = $target}).CreateGPO()
    

    [GPO]::new(@{gpoName = "DisableAnonymousSharesAccess"; gpoPath = "$Keypaths.LanmanServer"; gpoValue = "NullSessionShares"; type = MultiString; value = @(); target = $target}).CreateGPO()


    $LogPath = "C:\Users\sys32admin\Tools\PowerShellLogs.txt"
    $Keypath = "$Keypaths.HKLM_Policies + Ext\ScriptBlockLogging"

    New-GPO -Name "PowerShellLoggingGPO"
    Set-GPRegistryValue -Name $GPOName -Key $Keypath -ValueName "EnableModuleLogging" -Type "DWord" -Value 1
    Set-GPRegistryValue -Name $GPOName -Key $Keypath -ValueName "EnableScriptBlockLogging" -Type "DWord" -Value 1
    Set-GPRegistryValue -Name $GPOName -Key $Keypath -ValueName "LogPath" -Type String -Value $LogPath
    New-GPLink -Name $GPOName -Target $target


    $samObjectPath = "C:\Windows\System32\config\SAM"
    $acl = Get-Acl -Path $samObjectPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "Read", "Deny")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $samObjectPath -AclObject $acl

}
