' CyberZen - Silent Background Telemetry & ML Monitor
' Runs Python uvicorn backend silently in background with windowStyle = 0 (SW_HIDE)
' Ensures continuous 24/7 host threat monitoring whether the desktop UI is opened or closed.

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

strAppDir = "D:\CyberThreat_AI_System"
If Not fso.FolderExists(strAppDir) Then
    strAppDir = fso.GetAbsolutePathName(".")
End If

WshShell.CurrentDirectory = strAppDir

' Check if backend is already listening on port 8000 before launching
On Error Resume Next
Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP.6.0")
objHTTP.open "GET", "http://127.0.0.1:8000/api/health", False
objHTTP.setTimeouts 1000, 1000, 1000, 1000
objHTTP.send ""

If Err.Number = 0 Then
    If objHTTP.status = 200 Then
        ' Backend is already running actively, no duplicate needed
        WScript.Quit 0
    End If
End If
On Error GoTo 0

' Ensure data directory exists
strDataDir = strAppDir & "\data"
If Not fso.FolderExists(strDataDir) Then
    fso.CreateFolder(strDataDir)
End If

' Launch start_backend_silent.bat with windowStyle = 0 (completely hidden)
strBat = strAppDir & "\start_backend_silent.bat"
strCmd = "cmd.exe /c """ & strBat & """"
WshShell.Run strCmd, 0, False
