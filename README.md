# Windows-Path-Enumerate
This script fix vulnerability “Microsoft Windows Unquoted Service Path Enumeration” (Nessus plugin ID 63155) and similar problems with uninstall strings
Script modify values in the next registry keys: 
-   HKLM:\SYSTEM\CurrentControlSet\Services\ImagePath
-   HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UninstallString
-   HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\UninstallString

For getting full help for latest script could be used Windows_Path_Enumerate.ps1 -Help


## EXTRA IMPORTANT: Test script before use in production

# Example:

   -  Before
![Before Fix](/Content/before_service_fix.png)
   -  After
![After Fix](/Content/after_service_fix.png)


| [Vulnerability description](https://github.com/VectorBCO/windows-path-enumerate/wiki) | [Version history](https://github.com/VectorBCO/windows-path-enumerate/wiki/Version-History) | [Help from main script](https://github.com/VectorBCO/windows-path-enumerate/wiki/Help) | [Links](https://github.com/VectorBCO/windows-path-enumerate/wiki/Links) |
| :--: | :--: | :--: | :--: |