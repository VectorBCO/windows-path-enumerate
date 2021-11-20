BeforeDiscovery {
    $ErrorActionPreference = 'stop'
    Import-Module $PSScriptRoot\WPEPesterTestModule.ps1 -force 
}


Describe "Fix-options" {
    BeforeEach{
        Import-Module $PSScriptRoot\WPEPesterTestModule.ps1 -force 
        Import-TestRegistryKey
    }
    
    It "Silent & Passthru (fix needed)" {
        $LogPath = "$PSScriptRoot\ScriptOutput\Silent_True_Log.txt"
        $OutPut = . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent -LogName $LogPath
        $OutPut | should -Be $true
    }
    
    It "Script execution (services)" {
        $LogPath = "$PSScriptRoot\ScriptOutput\Service_Log.txt"
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -LogName $LogPath
        Test-Path $LogPath | should -Be $true
    }
    Verify-Logs -Number 1 -LogPath "$PSScriptRoot\ScriptOutput\Service_Log.txt"
    
    It "Script execution (software)" {
        $LogPath = "$PSScriptRoot\ScriptOutput\Software_Log.txt"
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices $False -LogName $LogPath
        Test-Path $LogPath | should -Be $true
    }
    Verify-Logs -Number 2 -LogPath "$PSScriptRoot\ScriptOutput\Software_Log.txt"

    It "Silent & Passthru (fix not needed - everything should be fixed)" {
        $LogPath = New-TemporaryFile
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -LogName $LogPath.Fullname
        $LogPath = "$PSScriptRoot\ScriptOutput\Silent_False_Log.txt"
        $OutPut = . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent -LogName $LogPath
        $OutPut | should -Be $false
    }

    It "Script execution with -FixEnv and create backup parameter (services & software)" {
        $LogPath = "$PSScriptRoot\ScriptOutput\SoftwareServicesAndFixEnv.txt"
        $BackupDir = "$PSScriptRoot\BackupDir"
        if (! (Test-Path $BackupDir)){
            New-Item $BackupDir -ItemType Directory
        }

        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -FixEnv -CreateBackup -BackupFolderPath $BackupDir -LogName $LogPath
        Test-Path $LogPath | should -Be $true
        $BackupFiles = Get-ChildItem $BackupDir -File | Select-Object -ExpandProperty Fullname
        # DBG
        #Write-Host ">>>>> Backup files:"
        #$BackupFiles | Out-Host
        ($BackupFiles | Measure-Object).Count | Should -BeGreaterOrEqual 8
    }
    Verify-Logs -Number 3 -LogPath "$PSScriptRoot\ScriptOutput\SoftwareServicesAndFixEnv.txt" -FixEnv

    <# ! TODO Add backup restore and verification that restore working fine
        $BackupDir contain 8 backup files:
        $PSScriptRoot\BackupDir\Service_Test_SrvEnvVar_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Service_Test_SrvMultiExe_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Service_Test_SrvWS_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Service_Test_SrvWSWithParameters_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Software_Test_APPEnvVar_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Software_Test_APPEnvVar_MultiExe_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Software_Test_APPWS_2020-06-30_221536.reg
        $PSScriptRoot\BackupDir\Software_Test_APPWSWithParameters_2020-06-30_221536.reg
    #>
}