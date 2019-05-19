<#
.SYNOPSIS
    Fix for Microsoft Windows Unquoted Service Path Enumeration

.DESCRIPTION
    Script for fixing vulnerability "Unquoted Service Path Enumeration" in Services and Uninstall strings. Script modifying registry values. 
    Require Administrator rights and should be runned on x64 powershell version in case if OS also have x64 architecture

.PARAMETER FixServices
    This bool parameter allow proceed Serives with vulnarability. By default this parameter enabled.
    For disabling this parameter use -FixServices:$False

.PARAMETER FixUninstall
    Parameter allow find and fix vulnarability in UninstallPaths.
    Will be covered pathes for x86 and x64 applications on x64 systems.

.PARAMETER FixEnv
    Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
    EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

.PARAMETER WhatIf
    Parameter should be used for checking possible system impact.
    With this parameter script would not change anything on your system,
    and only will show information about posible (needed) changes.

.PARAMETER CreateBackup
    When whick switch parameter enabled script will export registry tree`s
    specified for services or uninstall strings based on operator selection.
    Tree wuould be exported before any changes.

    [Note] For restoring backup could be used RestoreBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER RestoreBackup
    This parameter will allow restore previously created backup.
    If BackupName parameter would not be provided will be used last created backup,
    in other case script will try to find selected backup name

    [Note] For creation backup could be used CreateBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER BackupName
    Parameter would be proceeded only with CreateBackup or RestoreBackup
    If parameter would be provided, then path from this parameter would be used
    for creating or restoring registry keys.
    In case if RestoreBackup or CreateBackup switches would be seleected without
    providing value to BackupName parameter will be used C:\TMP\<Last Backup name>

    Example: C:\tmp\RegBackup-20190212.reg

.PARAMETER Help
    Will display how to get this help message

.PARAMETER Logname
    Parameter allow to change output file location, or disable logging setting this parameter tu empty string or $null.

.EXAMPLE
    # Run powershell as administrator and type path to this script. In case if it will not run type dot (.) before path.
    . C:\Scripts\Windows_Path_Enumerate.ps1


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  Computername: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 seervices 'BadDriver', 'NotAVirus'.
    Env variable %Programfiles% did not changed to full path in service 'BadDriver'


.EXAMPLE
    # This command, or simillar could be used for running script from SCCM
    Powershell -executionpolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -fixenv"


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  Computername: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 seervices 'BadDriver', 'NotAVirus'.
    Env variable %Programfiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

.EXAMPLE
    # This command, or simillar could be used for running script from SCCM
    Powershell -executionpolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices:$False -WhatIf"


VERBOSE:
--------
    2018-07-02 22:23:02Z  :  INFO  :  Computername: test
    2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
    2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


Description
-----------
    Script will find and displayed


.NOTES
    Name:  Windows_Path_Enumerate.PS1
    Version: 3.3.1
    Author: Vector BCO
    DateCreated: 20 Jan 2019

.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
    https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
    http://www.commonexploits.com/unquoted-service-paths/
#>

Param (
    [parameter(Mandatory=$false)]
    [Alias("s")]
        [Bool]$FixServices=$true,
    [parameter(Mandatory=$false)]
    [Alias("u")]
        [Switch]$FixUninstall,
    [parameter(Mandatory=$false)]
    [Alias("e")]
        [Switch]$FixEnv,
    [parameter(Mandatory=$false)]
    [Alias("ShowOnly")]
        [Switch]$WhatIf,
    [parameter(Mandatory=$false)]
    [Alias("h")]
        [switch]$Help,
    [System.IO.FileInfo]$Logname = "C:\Temp\ServicesFix-3.3.1.Log"

)

Function Write-FileLog {

    <#
    .SYNOPSIS
    Script writes array of strings to log file, if log file does not exist  tries to create new file at the selected path.
    Also it can skip Null strings and write info before and after string.
    Script is able to fill file logs and write an output to console simultaneously.


    .PARAMETER Value
    This parameter takes array of strings, basicaly by pipeline


    .PARAMETER Logname
    Log will be written in this file. If file does not exist, it will be created.
    If file exists, log will be appended
        Syntax.: "C:\temp\text.log"


    .PARAMETER AddAtBegin
    Parameter will be helpful if you need to add something at the beginning of every string,
    for example: date and time, or some trigers.
        Ex.: "String1`r`nString2" | Write-FileLog -AddAtBegin "$(get-date -UFormat '%d.%m.%Y %H:%m:%S')   : " -OutOnScreen -Logname C:\temp\text.log
        Out: 29.01.2017 12:01:26   : String1
             29.01.2017 12:01:26   : String2


    .PARAMETER AddToEnd
    The same as the AddAtBegin parameter, but value from this parameter will be added at the end of the string.


    .PARAMETER AddAtBeginRegOut
    The same as AddAtBegin parameter but work with OutRegexpMask switch.
    Parameter will work only if parameter OutRegexpMask is turned on and string matches to selected Regexp
    If string does not match to OutRegexpMask, then parameter AddAtBegin will work.
        Ex.: "String1`r`nString2" | Write-FileLog -Logname C:\temp\text.log `
                -AddAtBegin "$(get-date -UFormat '%d.%m.%Y %H:%m:%S')   : " `
                -OutRegexpMask '1$'-AddAtBeginRegOut "REGEXP Succesfully match at this string '" -AddToEndRegOut "'"
             Get-Content C:\temp\text.log

        Console: REGEXP Succesfully match at this string 'String1'

        File:
            REGEXP Succesfully match at this string 'String1'
            29.01.2017 14:01:55   : String2


    .PARAMETER AddToEndRegOut
    The same as AddToEnd parameter but work with OutRegexpMask switch.
    Parameter will work only if parameter OutRegexpMask is turned on and string matches to selected Regexp
    If string does not match to OutRegexpMask, then parameter AddToEnd will work.


    .PARAMETER SkipNullString
    If you do not need to see blank (null) string in the output, turn this parameter on.
        EX.: "String1`r`n`r`nString2" | Write-FileLog -SkipNullString -OutOnScreen -Logname C:\temp\text.log
        Out: String1
             String2


    .PARAMETER OutOnScreen
    If this switch parameter is chosen, text will be outputted in a file and on screen


    .PARAMETER OutRegexpMask
    Regexp trigger to write out some strings to console. (Read descriptions of AddAtBeginRegOut and AddToEndRegOut parameters as well).


    .EXAMPLE
    Get-ChildItem C:\temp | Out-String | Write-FileLog -OutOnScreen -Logname C:\temp\text.log


    VERBOSE:
    --------
        Directory: C:\temp


    Mode                LastWriteTime     Length Name
    ----                -------------     ------ ----
    -a---        29.01.2017     14:19       3182 text.log


    Description
    -----------
    The same as Out-File, but with output on console


    .EXAMPLE
    Get-ChildItem C:\temp | Out-String | Write-FileLog -OutOnScreen -Logname C:\temp\text.log -SkipNullString


    VERBOSE:
    --------
        Directory: C:\temp
    Mode                LastWriteTime     Length Name
    ----                -------------     ------ ----
    -a---        29.01.2017     14:19       3182 text.log


    Description
    -----------
    There are two blank strings between strings started with "Directory: ..." and "Mode ..." in previous Example , and parameter -SkipNullString removed them.

    .NOTES
        Name:  Write-FileLog
        Version: 1.0
        Author: Vector BCO
        DateCreated: 29 Jan 2017
        Link: https://gallery.technet.microsoft.com/Write-FileLog-Redirect-a91cdc2f
    #>

    Param (
        [parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
        [AllowEmptyString()]
        [AllowNull()]
            [String[]]$Value,
        [parameter(Mandatory=$true,
            Position=1)]
        [alias("File","Filename","FullName")]
        [ValidateScript({
            If (Test-Path $_){
                -NOT ((Get-Item $_).Attributes -like "*Directory*")
            }
            ElseIf (-NOT (Test-Path $_)){
                $Tmp = $_
                $Tmp -match '(?''path''^\w\:\\([^\\]+\\)+)(?''filename''[^\\]+)' | Out-Null
                $TmpPath = $Matches['path']
                $Tmpfilename = $Matches['filename']
                New-Item -ItemType Directory $TmpPath -Force -ErrorAction Stop
                New-Item -ItemType File $TmpPath$Tmpfilename -ErrorAction Stop
            } # End ElseIf blockk
        })] # End validate script
            [String]$Logname,
        [String]$AddAtBegin,
        [String]$AddToEnd,
        [String]$AddAtBeginRegOut,
        [String]$AddToEndRegOut,
        [switch]$SkipNullString,
        [switch]$OutOnScreen,
        [String]$OutRegexpMask
    ) # End Param block
    Begin {}
    Process {
        $Value -split '\n' | ForEach-Object {

            If ($SkipNullString -and (-not (([string]::IsNullOrEmpty($($_))) -or ([string]::IsNullOrWhiteSpace($($_)))))){
                If ([String]::IsNullOrEmpty($OutRegexpMask)){
                    If ($OutOnScreen){"$AddAtBegin$($_ -replace '\r')$AddToEnd"}
                    "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                } # End If
                ElseIf (![String]::IsNullOrEmpty($OutRegexpMask)){
                    If ($($_ -replace '\r') -match $OutRegexpMask){
                        Write-Output "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut"
                        "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut" | out-file $Logname -Append
                    } # End If
                    Else {
                        "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                    } # End Else
                } # End elseif
            } # End If
            ElseIF (-not ($SkipNullString)){
                If ([String]::IsNullOrEmpty($OutRegexpMask)){
                    If ($OutOnScreen){"$AddAtBegin$($_ -replace '\r')$AddToEnd"}
                    "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                } # End If
                ElseIf (![String]::IsNullOrEmpty($OutRegexpMask)){
                    If (($($_ -replace '\r') -match $OutRegexpMask) -or ([string]::IsNullOrEmpty($($_))) -or ([string]::IsNullOrWhiteSpace($($_)))){
                        Write-Output  "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut"
                        "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut" | out-file $Logname -Append
                    } # End If
                    Else {
                        "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                    } # End Else
                } # End elseif
            } # End elseif
        } # End Foreach
    } # End process
    End {}
} # End Function


Function Fix-ServicePath
{
    <#
    .SYNOPSIS
        Microsoft Windows Unquoted Service Path Enumeration

    .DESCRIPTION
        Use Fix-ServicePath to fix vulnerability "Unquoted Service Path Enumeration".

    .PARAMETER FixServices
        This switch parameter allow proceed Serives with vulnarability. By default this parameter enabled.
        For disable this parameter use -FixServices:$False

    .PARAMETER FixUninstall
        Parameter allow find and fix vulnarability in UninstallPath.
        Will be covered pathes for x86 and x64 applications on x64 systems.

    .PARAMETER FixEnv
        Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
        EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

    .PARAMETER WhatIf
        Parameter should be used for checking possible system impact.
        With this parameter script would not be changing anything on your system,
        and only will show information about posible changes

    .EXAMPLE
        Fix-Servicepath


    VERBOSE:
    --------
        2017-02-19 15:43:50Z  :  INFO  :  Computername: W8-NB
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
        2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
        2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
        2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
        2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

    Description
    -----------
        Fix 2 seervices 'BadDriver', 'NotAVirus'.
        Env variable %Programfiles% did not changed to full path in service 'BadDriver'


    .EXAMPLE
        Fix-Servicepath -FixEnv


    VERBOSE:
    --------
        2017-02-19 15:43:50Z  :  INFO  :  Computername: W8-NB
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
        2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
        2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
        2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
        2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
        2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

    Description
    -----------
        Fix 2 seervices 'BadDriver', 'NotAVirus'.
        Env variable %Programfiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

    .EXAMPLE
        Fix-Servicepath -FixUninstall -FixServices:$False -WhatIf


    VERBOSE:
    --------
        2018-07-02 22:23:02Z  :  INFO  :  Computername: test
        2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
        2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


    Description
    -----------
        Script will find and displayed


    .NOTES
        Name:  Fix-ServicePath
        Version: 3.4
        Author: Vector BCO
        Last Modified: 19 May 2019

    .LINK
        https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
        https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
        http://www.commonexploits.com/unquoted-service-paths/
    #>

    Param (
        [bool]$FixServices=$true,
        [Switch]$FixUninstall,
        [Switch]$FixEnv,
        [Switch]$WhatIf
    )

    Write-Output "$(get-date -format u)  :  INFO  : Computername: $($Env:COMPUTERNAME)"

    # Get all services
    $FixParameters = @()
    If ($FixServices){
        $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath"}
    }
    If ($FixUninstall){
        $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        # If OS x64 - adding pathes for x86 programs
        If (Test-Path "$($env:SystemDrive)\Program Files (x86)\"){
            $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        }
    }
    ForEach ($FixParameter in $FixParameters){
        Get-ChildItem $FixParameter.path -ErrorAction SilentlyContinue | ForEach-Object {
            $SpCharREGEX = '([\[\]])'
            $RegistryPath =$_.name -Replace 'HKEY_LOCAL_MACHINE', 'HKLM:' -replace $SpCharREGEX,'`$1'
            $OriginalPath = (Get-ItemProperty "$RegistryPath")
            $ImagePath = $OriginalPath.$($FixParameter.ParamName)
            If ($FixEnv){
                If ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%'){
                    $EnvVar = $Matches['envVar']
                    $FullVar = (Get-Childitem env: | Where-Object {$_.Name -eq $EnvVar}).value
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%",$FullVar
                    Clear-Variable Matches
                } # End If
            } # End If $fixEnv
            # Get all services with vulnerability
            If (($ImagePath -like "* *") -and ($ImagePath -notlike '"*"*') -and ($ImagePath -like '*.exe*')){
                # Skip MsiExec.exe in uninstall strings
                If ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?')) -or ($FixParameter.ParamName -eq 'ImagePath')){
                    $NewPath = ($ImagePath -split ".exe ")[0]
                    $key = ($ImagePath -split ".exe ")[1]
                    $triger = ($ImagePath -split ".exe ")[2]
                    $NewValue = ''
                    # Get service with vulnerability with key in ImagePath
                    If (-not ($triger | Measure-Object).count -ge 1){
                        If (($NewPath -like "* *") -and ($NewPath -notlike "*.exe")){
                            $NewValue = "`"$NewPath.exe`" $key"
                        } # End If
                        # Get service with vulnerability with out key in ImagePath
                        ElseIf (($NewPath -like "* *") -and ($NewPath -like "*.exe")){
                            $NewValue = "`"$NewPath`""
                        } # End ElseIf
                        If ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                            try {
                                $soft_service = $(if($FixParameter.ParamName -Eq 'ImagePath'){'Service'}Else{'Software'})
                                Write-Output "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))"
                                Write-Output "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue"
                                If (! $WhatIf){
                                    $OriginalPSPathOptimized = $OriginalPath.PSPath -replace $SpCharREGEX, '`$1'
                                    Set-ItemProperty -Path $OriginalPSPathOptimized -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                    $DisplayName = ''
                                    $keyTmp = (Get-ItemProperty -Path $OriginalPSPathOptimized)
                                    If ($soft_service -match 'Software'){
                                        $DisplayName =  $keyTmp.DisplayName
                                    }
                                    If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue){
                                        Write-Output "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'"
                                    } # End If
                                    Else {
                                        Write-Output "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                    } # End Else
                                } # End If
                            } # End try
                            Catch {
                                Write-Output "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                Write-Output "$(get-date -format u)  :  ERROR  : $_"
                            } # End Catch
                            Clear-Variable NewValue
                        } # End If
                    } # End Main If
                } # End if (Skip not needed strings)
            } # End If

            If (($triger | Measure-Object).count -ge 1) {
                Write-Output "$(get-date -format u)  :  ERROR  : Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') "
            } # End If
        } # End Foreach
    } # End Foreach
}

Function Get-OSandPoShArchitecture {
    # Check OS architecture
    if ((Get-WmiObject win32_operatingsystem | Select-Object osarchitecture).osarchitecture -eq "64-bit"){
        if ([intptr]::Size -eq 8){
            Return $true, $true
        } 
        Else {
            Return $true, $false
        }
    }
    else { Return $false, $false }
}

if ((! $FixServices) -and (! $FixUninstall)){
    Throw "Should be selected at least one of two parameters: FixServices or FixUninstall. `r`n For more details use 'get-help Windows_Path_Enumerate.ps1 -full'"
}
if ($Help){
    Write-Output "For help use this command in powershell: Get-Help $($MyInvocation.MyCommand.Path) -full"
    powershell -command "& Get-Help $($MyInvocation.MyCommand.Path) -full"
    exit
}

$OS, $PoSh = Get-OSandPoShArchitecture
If (($OS -eq $true) -and ($PoSh -eq $true)){
    $validation = "$(get-date -format u)  :  INFO  : Executed x64 Powershell on x64 OS"
} elseIf (($OS -eq $true) -and ($PoSh -eq $false)) {
    $validation =  "$(get-date -format u)  :  WARNING  : !ATTENTION! : Executed x32 Powershell on x64 OS. Not all vulnerabilities could be fixed.`r`n"
    $validation += "$(get-date -format u)  :  WARNING  : For fixing all vulnerabilities should be used x64 Powershell."
} else {
    $validation = "$(get-date -format u)  :  INFO  : Executed x32 Powershell on x32 OS"
}

if (! [string]::IsNullOrEmpty($Logname)){
    '*********************************************************************' | Write-FileLog -Logname $Logname
    $validation | Write-FileLog -Logname $Logname -OutOnScreen
    Fix-ServicePath `
        -FixUninstall:$FixUninstall `
        -FixServices:$FixServices `
        -WhatIf:$WhatIf `
        -FixEnv:$FixEnv | Write-FileLog -Logname $Logname -OutOnScreen
}
Else {
    Write-Output $validation
    Fix-ServicePath `
        -FixUninstall:$FixUninstall `
        -FixServices:$FixServices `
        -WhatIf:$WhatIf `
        -FixEnv:$FixEnv
}