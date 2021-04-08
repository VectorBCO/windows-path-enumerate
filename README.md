![CI](https://github.com/VectorBCO/windows-path-enumerate/workflows/CI/badge.svg)
![GitHub all releases](https://img.shields.io/github/downloads/VectorBCO/windows-path-enumerate/total?style=plastic)

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

# Links:
<table>
  <tr>
      <th><a href="https://github.com/VectorBCO/windows-path-enumerate/wiki">Vulnerability description</a></th>
      <th><a href="https://github.com/VectorBCO/windows-path-enumerate/wiki/Version-History">Version history</a></th>
      <th><a href="https://github.com/VectorBCO/windows-path-enumerate/wiki/Help">Help from main script</a></th>
      <th><a href="https://github.com/VectorBCO/windows-path-enumerate/wiki/Links">Links</a></th>
  </tr>
</table>
