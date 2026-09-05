<%@ Language="VBScript" %>
<%
' network diagnostics tool
Dim ip, sh, ex
ip = Request("ip")
If ip = "" Then ip = "127.0.0.1"
' FIXME: validate ip before handing it to the shell (ticket #4712)
Set sh = Server.CreateObject("WScript.Shell")
Set ex = sh.Exec("cmd.exe /c ping -n 1 " & ip & " 2>&1")
Response.Write "<pre>" & ex.StdOut.ReadAll() & "</pre>"
%>
