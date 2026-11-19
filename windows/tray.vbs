' Adamant: start the tray icon (windows\tray.ps1) as an independent hidden process.
' Started by server\runner.js (startTray). WScript.Shell.Run gives PowerShell its own hidden console and
' does not tie it to the Node process that asked for it, so the icon keeps running after that process exits.
' The only argument is the data folder; it must be an existing folder.
Option Explicit
Dim sh, fso, root, data, ps
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
If WScript.Arguments.Count <> 1 Then WScript.Quit 2
data = WScript.Arguments(0)
If InStr(data, """") > 0 Or Not fso.FolderExists(data) Then WScript.Quit 2
root = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))
ps = sh.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
sh.Run """" & ps & """ -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File """ & root & "\windows\tray.ps1"" -Root """ & root & """ -Data """ & data & """", 0, False
