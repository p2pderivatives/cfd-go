@echo off
setlocal
set PATH=%PATH%;%~dp0%\build\Release;
call go test -coverprofile=cover.out
REM call go tool cover -html=cover.out -o cover.html
call go tool cover -func=cover.out -o cover.txt
