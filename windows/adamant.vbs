' Adamant: start without a console window. Arguments go to server\launch.js (--tray, --background, --stop).
Option Explicit
Dim sh, fso, root, args, a, node
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))
args = ""
For Each a In WScript.Arguments
  If a = "--tray" Or a = "--background" Or a = "--stop" Then args = args & " " & a
Next
sh.CurrentDirectory = root
node = root & "\runtime\node.exe"
If Not fso.FileExists(node) Then node = "node"
sh.Run """" & node & """ """ & root & "\server\launch.js""" & args, 0, False
