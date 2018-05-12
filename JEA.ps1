break

#region ==== Set up AD accounts ===============================================

#endregion ====================================================================


#region ==== Clean up demo ====================================================

$ErrorActionPreference = 'SilentlyContinue'
'alice','bob','charlie' | ForEach-Object {Get-ADUser -Identity $_ | Remove-ADUser -Confirm:$false}
'GGStorage','GGNetwork' | ForEach-Object {Get-ADGroup -Identity $_ | Remove-ADGroup -Confirm:$false}
Get-PSSessionConfiguration |
    Where-Object {$_.Name -notin 'microsoft.powershell',
                                 'microsoft.powershell.workflow',
                                 'microsoft.powershell32',
                                 'microsoft.windows.servermanagerworkflows'} |
    ForEach-Object {Unregister-PSSessionConfiguration $_.Name}
#Remove-Item -Path WSMan:\localhost\Plugin\ContosoJEA -Recurse -Force -Confirm:$false
cd \
Remove-Item (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\ContosoJEA") -Force -Recurse
$ErrorActionPreference = 'Continue'

#endregion ====================================================================


#region ==== Set up AD accounts ===============================================

$Domain = $env:USERDOMAIN

$pw = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force
$cred_alice   = New-Object -TypeName PSCredential -ArgumentList "$Domain\alice",$pw
$cred_bob     = New-Object -TypeName PSCredential -ArgumentList "$Domain\bob",$pw
$cred_charlie = New-Object -TypeName PSCredential -ArgumentList "$Domain\charlie",$pw

$alice   = New-ADUser -Name Alice   -AccountPassword $pw -Enabled $true -PassThru
$bob     = New-ADUser -Name Bob     -AccountPassword $pw -Enabled $true -PassThru
$charlie = New-ADUser -Name Charlie -AccountPassword $pw -Enabled $true -PassThru

New-ADGroup -Name GGStorage -GroupCategory Security -GroupScope Global
New-ADGroup -Name GGNetwork -GroupCategory Security -GroupScope Global

Add-ADGroupMember -Identity GGStorage -Members $alice,$charlie
Add-ADGroupMember -Identity GGNetwork -Members $bob,$charlie

#endregion ====================================================================


#region ==== WinRM WSMan Remoting =============================================

Get-PSSessionConfiguration
# Notice permissions on Microsoft.PowerShell, the default endpoint...
# This is what you hit with Enter-PsSession or Invoke-Command.

# Remoting configuration
dir WSMan:\localhost
dir WSMan:\localhost\Service
dir WSMan:\localhost\Listener\Listener_1084132640

#endregion ====================================================================


#region ==== Setup JEA Module =================================================

# Create a folder for the module
$modulePath = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\ContosoJEA"

# Create an empty script module and module manifest.
New-Item -ItemType File -Path (Join-Path $modulePath "ContosoJEAFunctions.psm1") -Force
New-ModuleManifest -Path (Join-Path $modulePath "ContosoJEA.psd1") -RootModule "ContosoJEAFunctions.psm1"

# Create the RoleCapabilities folder and copy in the PSRC file
$rcFolder = Join-Path $modulePath "RoleCapabilities"
New-Item -ItemType Directory $rcFolder
Set-Location $rcFolder

# Observe the folder structure for JEA
Get-ChildItem $modulePath -Recurse

#endregion ====================================================================


#region ==== Scope capabilities ===============================================

# Constrained Language Mode
Get-Help New-PSRoleCapabilityFile
Get-Help about_Language_Modes

# Identify the modules to import and the command types
Get-Command -Name 'Sort-Object','Format-Table','Format-List' | Format-Table -AutoSize
Get-Command -Name 'Get-SmbShare','Get-ChildItem' | Format-Table -AutoSize
Get-Command -Name 'Get-Disk','Get-Volume','Get-Partition' | Format-Table -AutoSize
Get-Command -Name 'Get-NetAdapter','Test-NetConnection' | Format-Table -AutoSize
Get-Command -Name ping,ipconfig,whoami | Format-Table -AutoSize

#endregion ====================================================================


#region ==== Set up JEA =======================================================

$rc_disk = @{
    Description             = 'View Disks and Shares'
    ModulesToImport         = 'Storage','SmbShare' # Already imported by default: 'Microsoft.PowerShell.Management'
    VisibleAliases          = 'cd', 'dir','ft','fl'
    VisibleCmdlets          = 'Get-*Item','Set-Location','Sort-Object','Format-Table','Format-List'
    VisibleFunctions        = 'TabExpansion2','prompt','SmbShare\Get*','Storage\Get*'
    VisibleProviders        = 'FileSystem'
    VisibleExternalCommands = 'C:\Windows\System32\whoami.exe'
}
New-PSRoleCapabilityFile -Path .\ViewDisksAndShares.psrc @rc_disk

$rc_network = @{
    Description             = 'View Network'
    ModulesToImport         = 'NetAdapter', 'NetTCPIP'
    VisibleAliases          = 'ft','fl'
    VisibleCmdlets          = 'Sort-Object','Format-Table','Format-List'
    VisibleFunctions        = 'TabExpansion2','NetAdapter\Get*','NetTCPIP\Get*','Test-NetConnection'
    VisibleExternalCommands = 'C:\Windows\System32\whoami.exe','C:\Windows\System32\ping.exe','C:\Windows\System32\ipconfig.exe'
}
New-PSRoleCapabilityFile -Path .\ViewNetwork.psrc @rc_network

$pssc = @{
    SessionType         = 'RestrictedRemoteServer'
    LanguageMode        = 'NoLanguage'
    ExecutionPolicy     = 'Restricted'
    RunAsVirtualAccount = $true
    TranscriptDirectory = 'C:\JEATranscripts\'
    RoleDefinitions     = @{
        "$Domain\GGStorage" = @{ RoleCapabilities = 'ViewDisksAndShares' }
        "$Domain\GGNetwork" = @{ RoleCapabilities = 'ViewNetwork' }
    }
}
New-PSSessionConfigurationFile -Path .\JEAConfig.pssc @pssc

Test-PSSessionConfigurationFile -Path .\JEAConfig.pssc

Register-PSSessionConfiguration -Path .\JEAConfig.pssc -Name ContosoJEA

#endregion ====================================================================


#region ==== Test JEA =========================================================

Get-PSSessionCapability -ConfigurationName 'ContosoJEA' -Username "$Domain\alice"
Get-PSSessionCapability -ConfigurationName 'ContosoJEA' -Username "$Domain\bob"
Get-PSSessionCapability -ConfigurationName 'ContosoJEA' -Username "$Domain\charlie"

### DO NOT RUN THESE LINES IN VS CODE

$Domain = $env:USERDOMAIN
$pw = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force
$cred_alice   = New-Object -TypeName PSCredential -ArgumentList "$Domain\alice",$pw
$cred_bob     = New-Object -TypeName PSCredential -ArgumentList "$Domain\bob",$pw
$cred_charlie = New-Object -TypeName PSCredential -ArgumentList "$Domain\charlie",$pw

# Disks
Enter-PSSession -ComputerName . -ConfigurationName ContosoJEA -Credential $cred_alice

# Shares
Enter-PSSession -ComputerName . -ConfigurationName ContosoJEA -Credential $cred_bob

# Disks & Shares
Enter-PSSession -ComputerName . -ConfigurationName ContosoJEA -Credential $cred_charlie

#endregion ====================================================================


#region ==== Fingerprints =====================================================

dir C:\JEATranscripts

code (dir C:\JEATranscripts | Sort-Object LastWriteTime -Descending)[0].FullName

dir C:\JEATranscripts\ -Recurse | Sort-Object LastWriteTime | Where-Object Length -gt 0 | Select-String "Catch"

#endregion ====================================================================
