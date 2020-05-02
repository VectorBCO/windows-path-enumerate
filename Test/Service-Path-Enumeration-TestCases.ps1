$ErrorActionPreference = 'stop'

Function Import-TestRegistryKey {
    Get-ChildItem $PSScriptRoot\ -File | Where-Object { $_.Name -match '\.reg$' } | Foreach-Object {
        Write-Host "Importing $($_.Name)..."
        REGEDIT /s $_.FullName
    }
}

Function Get-RegexByName {
    param ([string]$Name)

    switch ($Name){
        "Test_SrvWS" {
            Write-Host "Test service with unquoted ImagePath"
            $Regex = [regex]::escape('"C:\Path with spaces\SrvWS.exe"')
        }
        "Test_SrvWSWithParameters" {
            Write-Host "Test service with unquoted ImagePath with Parameters"
            $Regex = [regex]::escape('"C:\Path with spaces\SrvWSWithParameters.exe" -parameter1 value1 -parameter2 value2')
        }
        "Test_SrvEnvVar" {
            Write-Host "Test service with ImagePath that contain env variable"
            $Regex = [regex]::escape('"%SystemDrive%\Path with spaces\SrvEnv_var.exe"')
        }
        "Test_SrvMultiExe"{
            Write-Host "Test service with ImagePath that contain multiple .exe"
            $Regex = [regex]::escape('"C:\Path with spaces\SrvMulti.exe" -parameter c:\Some Path\Some file.exe')
        }
        default {$Regex = ''}
    }
    return $Regex
}


Function Verify-Logs {
    param(
        $LogPath,
        $Number
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
                $regex = Get-RegexByName -Name $Name
                if (! [string]::IsNullOrEmpty($regex)) {
                    $TestCases += @{ Name = "$Name" ; Type = "$Type" ; RegExpression = $regex ; LogContent = $LogContent}
                }
            }
        }

        It "Test cases exists #$Number" {
            ($TestCases | Measure-Object).Count | Should -BeGreaterThan 0
        }

        It "[<Type>] <Name> (w\o backup)" -TestCases $TestCases {
            Param (
                $Name,
                $Type,
                $RegExpression,
                $LogContent
            )
            $NextShouldBeSuccess = $false
            $LogContent -split '\r\n' | Foreach-Object {
                $String = $_ 
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
    $LogPath = "$PSScriptRoot\ScriptOutput\Service_Log.txt"
    It "Silent & Passthru (fix need)" {
        $OutPut = . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -LogName $LogPath -FixUninstall -WhatIf -Passthru -Silent -LogName ''
        $OutPut | should -Be $true
    }

    It "Script execution (services w\o parameters)" {
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -LogName $LogPath
        Test-Path $LogPath | should -Be $true
    }

    Verify-Logs -Number 1 -LogPath $LogPath

    $LogPath = "$PSScriptRoot\ScriptOutput\Software_Log.txt"
    It "Script execution (services w\o parameters)" {
        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices $False -LogName $LogPath
        Test-Path $LogPath | should -Be $true
    }

    Verify-Logs -Number 2 -LogPath $LogPath

    It "Silent & Passthru (fix not needed - everything should be fixed)" {
        $OutPut = . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -LogName $LogPath -FixUninstall -WhatIf -Passthru -Silent -LogName ''
        $OutPut | should -Be $false
    }
}