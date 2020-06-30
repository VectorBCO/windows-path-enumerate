$ErrorActionPreference = 'stop'

Function Import-TestRegistryKey {
    Get-ChildItem $PSScriptRoot\ -File | Where-Object { $_.Name -match '\.reg$' } | Foreach-Object {
        Write-Host "Importing $($_.Name)..."
        REGEDIT /s $_.FullName
    }
}

Function Get-RegexByName {
    param (
        [string]$Name,
        [bool]$FixEnv
    )

    switch ($Name){
#------------------------------- Service -----------------------------
        "Test_SrvWS" {
            Write-Host "[Service] 'Test_SrvWS' with unquoted ImagePath"
            $Regex = [regex]::escape('"C:\Path with spaces\SrvWS.exe"')
        }
        "Test_SrvWSWithParameters" {
            Write-Host "[Service] 'Test_SrvWSWithParameters' service with unquoted ImagePath with Parameters"
            $Regex = [regex]::escape('"C:\Path with spaces\SrvWSWithParameters.exe" -parameter1 value1 -parameter2 value2')
        }
        "Test_SrvEnvVar" {
            Write-Host "[Service] 'Test_SrvEnvVar' with ImagePath that contain env variable"
            $str = '"%SystemDrive%\Path with spaces\SrvEnv_var.exe"'
            if ($FixEnv){$str = $str -replace '%SystemDrive%',$Env:SystemDrive}
            $Regex = [regex]::escape($str)
        }
        "Test_SrvMultiExe"{
            Write-Host "[Service] 'Test_SrvMultiExe' with ImagePath that contain multiple .exe"
            $Regex = [regex]::escape('"C:\Path with spaces\SrvMulti.exe" -parameter c:\Some Path\Some file.exe')
        }
#------------------------------- Software -----------------------------
        "Test_APPWS"{
            Write-Host "[Software] 'Test_APPWS' with unquoted Uninstall String"
            $Regex = [regex]::escape('"C:\Path with spaces\APPWS.exe"')
        }
        "Test_APPWSWithParameters"{
            Write-Host "[Software] 'Test_APPWSWithParameters' with unquoted Uninstall String with Parameters"
            $Regex = [regex]::escape('"C:\Path with spaces\APPSWithParameters.exe" -parameter1 value1 -parameter2 value2')
        }
        "Test_APPEnvVar"{
            Write-Host "[Software] 'Test_APPEnvVar' with unquoted Uninstall String with Parameters"
            $str = '"%SystemDrive%\Path with spaces\APPEnv_var.exe"'
            if ($FixEnv){$str = $str -replace '%SystemDrive%',$Env:SystemDrive}
            $Regex = [regex]::escape($str)
        }
        "Test_APPEnvVar_MultiExe"{
            Write-Host "[Software] 'Test_APPEnvVar_MultiExe' with unquoted Uninstall String with Parameters"
            $str = '"%SystemDrive%\Path with spaces\APPMulti.exe" -uninstall c:\Some Path\Some file.exe'
            if ($FixEnv){$str = $str -replace '%SystemDrive%',$Env:SystemDrive}
            $Regex = [regex]::escape($str)
        }
        # Test_AppShouldNotBeDetected  "Test application with  Uninstall String that contain multiple .exe"
        default {$Regex = ''}
    }
    return $Regex
}


Function Verify-Logs {
    param(
        $LogPath,
        $Number,
        [switch]$FixEnv
    )
    # If script was executed successfully this block will analyze it
    if (Test-Path $LogPath){
        $LogContent = Get-Content $LogPath

        # Log file contain some records
        It "Log not empty #$Number" {
            $LogContent | Should -Not -Be $null
        }

        $TestCases = @()
        $LogContent -split '\r\n' | Where-Object {$_ -match 'Expected'} | Foreach-Object {
            $string = $_
            $Name = ''
            $Type = ''
            $regex = ''
            if ($string -match 'Expected\s+:\s+(?''Type''(Service|Software))\s+:\s+''(?''Name''[^'']+)''') {
                $Name = $Matches['Name']
                $Type = $Matches['Type']
                $regex = Get-RegexByName -Name $Name -FixEnv $FixEnv
                if (! [string]::IsNullOrEmpty($regex)) {
                    $TestCases += @{ Name = "$Name" ; Type = "$Type" ; RegExpression = $regex ; LogContent = $LogContent}
                }
            }
        }

        It "Test cases exists #$Number" {
            ($TestCases | Measure-Object).Count | Should -BeGreaterThan 0
        }

        It "[<Type>][#$Number] <Name>" -TestCases $TestCases {
            Param (
                $Name,
                $Type,
                $RegExpression,
                $LogContent
            )
            $NextShouldBeSuccess = $false
            $BackupFindInALog = $false
            Foreach ($String in ($LogContent -split '\r\n')) {
                if ($string -match 'Creating registry backup') {
                    $BackupFindInALog = $true
                    # If backups will be created then this line should be skipped from the log
                    continue
                } elseif ($BackupFindInALog -and ($string -match 'The operation completed successfully')) {
                    $BackupFindInALog = $false
                    # If backups will be created then this line should be skipped from the log
                    continue
                }
                if ($NextShouldBeSuccess) {
                    $NextShouldBeSuccess = $false
                    $string | Should -Match "Success.+'$Name'"
                    break
                } # End If (Change was successful)
                if ($string -match "Expected\s+:\s+$Type\s+:\s+'$Name'") {
                    $NextShouldBeSuccess = $true
                    $String | Should -Match $RegExpression
                } # End If (Path validation)
            } # End Foreach
        } # Checking logs that all services was successfully fixed
    }
}

Describe "Fix-options" {
    Import-TestRegistryKey
    $LogPath = "$PSScriptRoot\ScriptOutput\Silent_True_Log.txt"
    It "Silent & Passthru (fix need)" {
        $OutPut = . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent -LogName $LogPath
        $OutPut | should -Be $true
    }

    $LogPath = "$PSScriptRoot\ScriptOutput\Service_Log.txt"
    It "Script execution (services)" {
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -LogName $LogPath
        Test-Path $LogPath | should -Be $true
    }
    Verify-Logs -Number 1 -LogPath $LogPath

    $LogPath = "$PSScriptRoot\ScriptOutput\Software_Log.txt"
    It "Script execution (software)" {
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices $False -LogName $LogPath
        Test-Path $LogPath | should -Be $true
    }
    Verify-Logs -Number 2 -LogPath $LogPath

    $LogPath = "$PSScriptRoot\ScriptOutput\Silent_False_Log.txt"
    It "Silent & Passthru (fix not needed - everything should be fixed)" {
        $OutPut = . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -WhatIf -Passthru -Silent -LogName $LogPath
        $OutPut | should -Be $false
    }

    Import-TestRegistryKey
    $LogPath = "$PSScriptRoot\ScriptOutput\SoftwareServicesAndFixEnv.txt"
    $BackupDir = "$PSScriptRoot\BackupDir"
    if (! (Test-Path $BackupDir)){
        New-Item $BackupDir -ItemType Directory
    }
    It "Script execution with -FixEnv and create backup parameter (services & software)" {
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -FixEnv -CreateBackup -BackupFolderPath $BackupDir -LogName $LogPath
        Test-Path $LogPath | should -Be $true
        $BackupFiles = Get-ChildItem $BackupDir -File | Select-Object -ExpandProperty Fullname
        Write-Host "Backup files:"
        $BackupFiles | Out-Host
        ($BackupFiles | Measure-Object).Count | Should -BeGreaterOrEqual 8
    }
    Verify-Logs -Number 3 -LogPath $LogPath -FixEnv
}