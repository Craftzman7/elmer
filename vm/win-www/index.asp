<%@ Language="VBScript" %>
<%
Dim host
host = Request.ServerVariables("SERVER_NAME")
%>
<!doctype html>
<html>
<head><title><%= host %> - service status</title></head>
<body style="font-family: monospace; max-width: 40em; margin: 4em auto;">
<h1><%= host %> service status</h1>
<ul>
  <li>IIS - serving this page</li>
  <li>nightly backups - handled by svc_backup</li>
  <li><a href="/ping.asp">network diagnostics (ping)</a></li>
</ul>
</body>
</html>
