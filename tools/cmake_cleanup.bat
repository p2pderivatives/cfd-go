setlocal
@echo off

if exist "cmake_cleanup.bat" (
  cd ..
)

if exist build rmdir /S /Q build

if exist external\cfd rmdir /S /Q external\cfd

if exist external\cfd-core rmdir /S /Q external\cfd-core

if exist external\libwally-core rmdir /S /Q external\libwally-core

if exist external\googletest rmdir /S /Q external\googletest
