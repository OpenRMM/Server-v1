@ECHO OFF
:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------
Xcopy /E /I /Y Source C:\OpenRMM\Server
CD C:\OpenRMM\Server\EXE
echo Installing Python
python-3.10.1-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 TargetDir=C:\Python\ DefaultAllUsersTargetDir=C:\Python\ Include_test=0
cd ..
echo Installing Required Modules
py -m pip install paho-mqtt
py -m pip install pywin32
py -m pip install pyzmq
py -m pip install rsa
py -m pip install cryptography
py -m pip install pycryptodome
py -m pip install pymysql
py -m pip install dictdiffer
py -m pip install psutil

echo Moving DLLs
echo moving C:\Python\Lib\site-packages\pywin32_system32
Xcopy /E /I /Y C:\Python\Lib\site-packages\pywin32_system32 C:\Python\Lib\site-packages\win32
cd Py
echo Installing OpenRMM Server
py Server.py --startup auto install
py Server.py start

echo Installing Git
winget install --id Git.Git -e --source winget
pause