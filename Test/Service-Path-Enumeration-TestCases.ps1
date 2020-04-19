$ErrorActionPreference = 'stop'

Install-Module pester -force -Confirm:$false -Scope CurrentUser -SkipPublisherCheck
Set-Location $ENV:GITHUB_WORKSPACE\Test\
Import-Module Pester -Force

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
    }
    return $Regex
}

Describe "Fix-options" {
    Import-TestRegistryKey

    It "Service fix" {
        $LogPath = "$PSScriptRoot\ScriptOutput\Log.txt"
        $NextShouldBeSuccess = $false

        . $PSScriptRoot\..\Windows_Path_Enumerate.ps1 -LogName $LogPath
        Test-Path $LogPath | should -Be $true
        $LogContent = Get-Content $LogPath
        $LogContent -split '\r\n' | Foreach-Object {
            $string = $_ 
            if ($string -match 'Expected'){
                $NextShouldBeSuccess = $true
                if ($string -match 'Expected\s+:\s+Service\s+:\s+''(?''Name''[^'']+)''') {
                    $Name = $Matches['Name']
                }
                $regex = Get-RegexByName -Name $Name
                $string | Should -Match $Regex
            }
            if ($NextShouldBeSuccess) {
                $NextShouldBeSuccess = $false
                $string | Should -Match "Success"
            }
        }
    } # End "Service fix should generate file log"
}