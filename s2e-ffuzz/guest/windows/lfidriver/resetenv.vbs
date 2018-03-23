Set oShell = WScript.CreateObject("WScript.Shell")
filename = oShell.ExpandEnvironmentStrings("%TEMP%\resetvars.bat")
Set objFileSystem = CreateObject("Scripting.fileSystemObject")
Set oFile = objFileSystem.CreateTextFile(filename, TRUE)

set pEnv=oShell.Environment("Process")
for each sitem in pEnv
    s = Split(sitem, "=")
	if StrComp(s(0), "") <> 0 and StrComp(s(0), "SystemRoot", 1) <> 0 	and StrComp(s(0), "SystemDrive", 1) <> 0 then
		oFile.WriteLine("SET " & s(0) & "=")
	end if
next

set oEnv=oShell.Environment("Volatile")
for each sitem in oEnv
    oFile.WriteLine("SET " & sitem)
next

set oEnv=oShell.Environment("System")
for each sitem in oEnv
    oFile.WriteLine("SET " & sitem)
next
path = oEnv("PATH")

set oEnv=oShell.Environment("User")
for each sitem in oEnv
    oFile.WriteLine("SET " & sitem)
next

path = path & ";" & oEnv("PATH")
oFile.WriteLine("SET PATH=" & path)
oFile.Close