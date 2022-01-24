@echo off

set update_url=%1

IF "%1"=="" (
    set update_url="https://github.com/OpenRMM/Server.git"
)

CD C:\OpenRMM\
git clone %update_url% temp
xcopy /e /v /XN temp\source\ Server\

CD C:\OpenRMM\Server\Py
py Server.py update
py Server.py start
::start py OpenRMM.py debug
EXIT