setlocal
@echo off

if exist "cmake_cleanup.bat" (
  cd ..
)

rmdir /S /Q build

rmdir /S /Q external\cfd

rmdir /S /Q external\cfd-core

rmdir /S /Q external\libwally-core

