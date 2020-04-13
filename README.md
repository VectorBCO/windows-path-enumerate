# Windows-Path-Enumerate
This script fix vulnerability “Microsoft Windows Unquoted Service Path Enumeration” (Nessus plugin ID 63155) and similar problems with uninstall strings
Script modify values in the next registry keys: 
-   HKLM:\SYSTEM\CurrentControlSet\Services\ImagePath
-   HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UninstallString
-   HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\UninstallString

For getting full help for latest script could be used Windows_Path_Enumerate.ps1 -Help

# Vulnerability description
Full description can be find [here](https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration)

## EXTRA IMPORTANT: Test script before use in production

# Version history:

##   3.4 Download link **[here](https://github.com/VectorBCO/windows-path-enumerate/tree/Version-3.4)**:
###     Release notes:
1.   Backup restore functionality added  
2.   Fixed defect with uninstall strings that start with "RunDll32"
3.   Write-FileLog custom function replaced with tee-object
4.   Fixed defect with saving logs and backups on a network drive
5.   Minor non functional fixes

##   3.3.2 Download link **[here](https://github.com/VectorBCO/windows-path-enumerate/tree/Version-3.3.2)**:
###     Release notes:
1.  Added fix, for issue reported by RafalPolandB (Q/A block):
    * Previous script version skips services and processes which contains "[" and "]" brackets in the name.
    * Test [results](https://drive.google.com/open?id=1oNgw_BtyEwAwa55GcFilUJrcclh5E_Qz), where service name marked red, and value with special characters marked green.

##   3.3.1 Download link **[here](https://github.com/VectorBCO/windows-path-enumerate/tree/Version-3.3.1)**:
###     Release notes:
    *Main functions was not changed

1.   Removed pre-definition for whatif parameter
2.   Added script readme and help parameter which will display it.
3.   Added samples for running script from SCCM or similar systems
4.   Added param LogName and possibility disable logging
5.   Added powershell and os version clarification for problem solving (popular notes in QA block)

##   3.3 Download link **[here](https://github.com/VectorBCO/windows-path-enumerate/tree/Version-3.3)**:
###     Release notes:
1.   Added possibility for fix UninstallStrings.
2.   Added 3 switch parameters for enabling\disabling\debugging:
    * FixServices Enabled by default. Execution the same command as in v.3.2 should make similar changes. For disabling this parameter, use -FixServices:$False
    * FixUninstall Requested feature for fixing Uninstall strings. From now this switch turned off by default
    * WhatIf Working as WhatIf parameter in many other commands - retuning information, but not making changes

##   3.2 Download link **[here](https://github.com/VectorBCO/windows-path-enumerate/tree/Version-3.2)**:
###     Release notes:
1.   Code optimized. Added verification block. If operation finished successfully you got a message, otherwise you get error report on screen and in to the file log.
2.   Added function Write-FileLog for easy output information to the log file and to console (similar to tee-object)
3.   Added switch -FixEnv for fix environment variables. This switch replace Env. variable to their values. EX.: %ProgramFiles% -> "C:\Program Files"

##   3.1 Download link **[here](https://github.com/VectorBCO/windows-path-enumerate/tree/Version-3.1)**:
    First published version (tested in production)



# Example:

   -  Before
![Before Fix](/Content/before_service_fix.png)
   -  After
![After Fix](/Content/after_service_fix.png)


# Help from main script

```PowerShell
<#
.SYNOPSIS
    Fix for Microsoft Windows Unquoted Service Path Enumeration

.DESCRIPTION
    Script for fixing vulnerability "Unquoted Service Path Enumeration" in Services and Uninstall strings. Script modifying registry values. 
    Require Administrator rights and should be run on x64 powershell version in case if OS also have x64 architecture

.PARAMETER FixServices
    This bool parameter allow proceed Services with vulnerability. By default this parameter enabled.
    For disabling this parameter use -FixServices:$False

.PARAMETER FixUninstall
    Parameter allow find and fix vulnerability in UninstallPaths.
    Will be covered paths for x86 and x64 applications on x64 systems.

.PARAMETER FixEnv
    Find services with Environment variables in the ImagePath parameter, and replace Env. variable to the it value
    EX. %ProgramFiles%\service.exe will be replace to "C:\Program Files\service.exe"

.PARAMETER WhatIf
    Parameter should be used for checking possible system impact.
    With this parameter script would not change anything on your system,
    and only will show information about possible (needed) changes.

.PARAMETER CreateBackup
    When switch parameter enabled script will export registry tree`s
    specified for services or uninstall strings based on operator selection.
    Tree would be exported before any changes.

    [Note] For restoring backup could be used RestoreBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER RestoreBackup
    This parameter will allow restore previously created backup.
    If BackupName parameter would not be provided will be used last created backup,
    in other case script will try to find selected backup name

    [Note] For creation backup could be used CreateBackup parameter
    [Note] For providing full backup path could be used BackupName parameter

.PARAMETER BackupFolderPath
    Parameter would be proceeded only with CreateBackup or RestoreBackup
    If CreateBackup or RestoreBackup parameter will be provided, then path from this parameter will be used.

    During backup will be created reg file with original values per each service and application that will be modified
    During restoration all reg files in the specified format will be iterable imported to the registry

    Input example: C:\Backup\

    Backup file format:
      for -FixServices switch => Service_<ServiceName>_YYYY-MM-DD_HHmmss.reg
      for -FixUninstall switch => Software_<ApplicationName>_YYYY-MM-DD_HHmmss.reg

.PARAMETER Help
    Will display how to get this help message

.PARAMETER LogName
    Parameter allow to change output file location, or disable logging setting this parameter to empty string or $null.

.EXAMPLE
    # Run powershell as administrator and type path to this script. In case if it will not run type dot (.) before path.
    . C:\Scripts\Windows_Path_Enumerate.ps1


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "%ProgramFiles%\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - C:\Program Files\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Program Files\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 services 'BadDriver', 'NotAVirus'.
    Env variable %ProgramFiles% did not changed to full path in service 'BadDriver'


.EXAMPLE
    # This command, or similar could be used for running script from SCCM
    Powershell -ExecutionPolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixEnv"


VERBOSE:
--------
    2017-02-19 15:43:50Z  :  INFO  :  ComputerName: W8-NB
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'BadDriver' - %ProgramFiles%\bad driver\driver.exe -k -l 'oper'
    2017-02-19 15:43:50Z  :  Expected  :  Service: 'BadDriver' - "C:\Program Files\bad driver\driver.exe" -k -l 'oper'
    2017-02-19 15:43:50Z  :  SUCCESS  : New Value of ImagePath was changed for service 'BadDriver'
    2017-02-19 15:43:50Z  :  Old Value :  Service: 'NotAVirus' - %SystemDrive%\Strange Software\virus.exe -silent
    2017-02-19 15:43:51Z  :  Expected  :  Service: 'NotAVirus' - "C:\Strange Software\virus.exe" -silent'
    2017-02-19 15:43:51Z  :  SUCCESS  : New Value of ImagePath was changed for service 'NotAVirus'

Description
-----------
    Fix 2 services 'BadDriver', 'NotAVirus'.
    Env variable %ProgramFiles% replaced to full path 'C:\Program Files' in service 'BadDriver'

.EXAMPLE
    # This command, or similar could be used for running script from SCCM
    Powershell -ExecutionPolicy bypass -command ". C:\Scripts\Windows_Path_Enumerate.ps1 -FixUninstall -FixServices:$False -WhatIf"


VERBOSE:
--------
    2018-07-02 22:23:02Z  :  INFO  :  ComputerName: test
    2018-07-02 22:23:04Z  :  Old Value : Software : 'FakeSoft32' - c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe -silent
    2018-07-02 22:23:04Z  :  Expected  : Software : 'FakeSoft32' - "c:\Program files (x86)\Fake inc\Pseudo Software\uninstall.exe" -silent


Description
-----------
    Script will find and displayed


.NOTES
    Name:  Windows_Path_Enumerate.PS1
    Version: 3.4
    Author: Vector BCO
    Updated: 11 Apr 2020

.LINK
    https://github.com/VectorBCO/windows-path-enumerate/
    https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341
    https://www.tenable.com/sc-report-templates/microsoft-windows-unquoted-service-path-enumeration
    http://www.commonexploits.com/unquoted-service-paths/
#>
```