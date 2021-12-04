Function Get-RegexByName {
    param (
        [string]$Name,
        [bool]$FixEnv
    )

    switch ($Name){
        #------------------------------- Services -----------------------------
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
} # End Function Get-RegexByName

Function Verify-Logs {
    param(
        $LogPath,
        $Number,
        [switch]$FixEnv
    )
    # If script was executed successfully this block will analyze it
    if (Test-Path $LogPath){
        $LogContent = Get-Content $LogPath

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

        It "[<Type>][#$Number] <Name>" -TestCases $TestCases {
            Param (
                $Name,
                $Type,
                $RegExpression,
                $LogContent
            )
            $LogContent | Should -Not -Be $null

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
    } # End If (Log path exists)
} # End Function Verify-Logs

Function Import-TestRegistryKey {
    Get-ChildItem $PSScriptRoot\ -File | Where-Object { $_.Name -match '\.reg$' } | Foreach-Object {
        Write-Host "Importing $($_.Name)..."
        REGEDIT /s $_.FullName
    }
} # End Function Import-TestRegistryKey
