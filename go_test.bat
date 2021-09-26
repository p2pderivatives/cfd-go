@echo off
setlocal
set PATH=%PATH%;%~dp0%\build\Release;
call go test . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests -v
