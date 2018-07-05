Clear-Host

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
    ) # End Func block
    begin {}
    process {
        $Value -split '\n' | foreach {

            If ($SkipNullString -and (-not (([string]::IsNullOrEmpty($($_))) -or ([string]::IsNullOrWhiteSpace($($_)))))){
                if ([String]::IsNullOrEmpty($OutRegexpMask)){
                    If ($OutOnScreen){"$AddAtBegin$($_ -replace '\r')$AddToEnd"}
                    "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                } # End If
                elseif (![String]::IsNullOrEmpty($OutRegexpMask)){
                    If ($($_ -replace '\r') -match $OutRegexpMask){
                        "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut"
                        "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut" | out-file $Logname -Append
                    } # End If
                    Else {
                        "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                    }
                } # End elseif
            } # End If
            ElseIF (-not ($SkipNullString)){
                if ([String]::IsNullOrEmpty($OutRegexpMask)){
                    If ($OutOnScreen){"$AddAtBegin$($_ -replace '\r')$AddToEnd"}
                    "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                } # End If
                elseif (![String]::IsNullOrEmpty($OutRegexpMask)){
                    If (($($_ -replace '\r') -match $OutRegexpMask) -or ([string]::IsNullOrEmpty($($_))) -or ([string]::IsNullOrWhiteSpace($($_)))){
                        "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut"
                        "$AddAtBeginRegOut$($_ -replace '\r')$AddToEndRegOut" | out-file $Logname -Append
                    } # End If
                    Else {
                        "$AddAtBegin$($_ -replace '\r')$AddToEnd" | out-file $Logname -Append
                    } # End Else
                } # End elseif
            } # End elseif
        } # End Foreach
    } # End process
    end {}
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
        Version: 3.3
        Author: Vector BCO 
        DateCreated: 06 Jul 2018 

	.LINK
		https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
		https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
		http://www.commonexploits.com/unquoted-service-paths/
    #>
    
    Param (
        [Switch]$FixServices=$true,
        [Switch]$FixUninstall,
        [Switch]$FixEnv,
        [Switch]$WhatIf
    ) 

    "$(get-date -format u)  :  INFO  :  Computername: $($Env:COMPUTERNAME)" 

    # Get all services
    $FixParameters = @()
    if ($FixServices){
        $FixParameters += @{"Path" = "HKLM:\SYSTEM\CurrentControlSet\Services\" ; "ParamName" = "ImagePath"}
    }
    if ($FixUninstall){
        $FixParameters += @{"Path" = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        # If OS x64 - adding pathes for x86 programs 
        If (Test-Path "$($env:SystemDrive)\Program Files (x86)\"){
            $FixParameters += @{"Path" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ; "ParamName" = "UninstallString"}
        }
    }
    foreach ($FixParameter in $FixParameters){
        Get-ChildItem $FixParameter.path | foreach {
            $OriginalPath = (Get-ItemProperty "$($($_).name.replace('HKEY_LOCAL_MACHINE', 'HKLM:'))")
            $ImagePath = $OriginalPath.$($FixParameter.ParamName)
            if ($FixEnv){
                if ($($OriginalPath.$($FixParameter.ParamName)) -match '%(?''envVar''[^%]+)%'){
                    $EnvVar = $Matches['envVar']
                    $FullVar = (Get-Childitem env: | Where {$_.Name -eq $EnvVar}).value
                    $ImagePath = $OriginalPath.$($FixParameter.ParamName) -replace "%$EnvVar%",$FullVar
                    Clear-Variable Matches
                } # 
            } # End If $fixEnv
            #Write-Host "Original path $ImagePath" -ForegroundColor Yellow
            # Get all services with vulnerability
            If (($ImagePath -like "* *") -and ($ImagePath -notlike '"*"*') -and ($ImagePath -like '*.exe*')){ 
                # Skip MsiExec.exe in uninstall strings
                if ((($FixParameter.ParamName -eq 'UninstallString') -and ($ImagePath -NotMatch 'MsiExec(\.exe)?')) -or ($FixParameter.ParamName -eq 'ImagePath')){

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
                    
                        #Write-Host "New path $NewValue" -ForegroundColor green
                        
                        #<#
                        if ((-not ([string]::IsNullOrEmpty($NewValue))) -and ($NewPath -like "* *")) {
                            try {
                                $soft_service = $(if($FixParameter.ParamName -Eq 'ImagePath'){'Service'}Else{'Software'})

                                "$(get-date -format u)  :  Old Value : $soft_service : '$($OriginalPath.PSChildName)' - $($OriginalPath.$($FixParameter.ParamName))" 
                                "$(get-date -format u)  :  Expected  : $soft_service : '$($OriginalPath.PSChildName)' - $NewValue" 
                                If (! $WhatIf){
                                    
                                    Set-ItemProperty -Path $OriginalPath.PSPath -Name $($FixParameter.ParamName) -Value $NewValue -ErrorAction Stop
                                    
                                    $DisplayName = ''
                                    $keyTmp = (Get-ItemProperty -Path $OriginalPath.PSPath)
                                    if ($soft_service -match 'Software'){
                                        $DisplayName =  $keyTmp.DisplayName
                                    }
                                    If ($keyTmp.$($FixParameter.ParamName) -eq $NewValue){
                                        "$(get-date -format u)  :  SUCCESS  : Path value was changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'" 
                                    } # End If
                                    Else {
                                        "$(get-date -format u)  :  ERROR  : Something is going wrong. Path was not changed for $soft_service '$(if($DisplayName){$DisplayName}else{$OriginalPath.PSChildName})'."
                                    } # End Else 
                                }
                            } # End try
                            Catch {
                                "$(get-date -format u)  :  ERROR  : Something is going wrong. Value changing failed in service '$($OriginalPath.PSChildName)'."
                                "$(get-date -format u)  :  ERROR  :  $($Error[0].Exception.Message)"
                            } # End Catch
                            Clear-Variable NewValue
                        } # End If
                        #>
                    } # End Main If
                } #End if (Skip not needed strings) 
            }
            
            If (($triger | Measure-Object).count -ge 1) { 
                "$(get-date -format u)  :  ERROR  :  Can't parse  $($OriginalPath.$($FixParameter.ParamName)) in registry  $($OriginalPath.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry\:\:') " 
            }
        } # End Foreach
    }
}




#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Script Started Here 
$Logname = "C:\Temp\ServicesFix-3.3.Log"
'*********************************************************************' | Write-FileLog -Logname $Logname


<# 
If You need to modify environment variables in service path you shold to use -FixEnv key
EX.: Fix-ServicePath -FixEnv
If ImagePath contain for example '%Programfile%' it will be replaced to 'C:\Program Files'
#>
Fix-ServicePath -FixUninstall -FixServices -WhatIf | Write-FileLog -Logname $Logname -OutOnScreen