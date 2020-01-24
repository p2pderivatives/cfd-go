setlocal
@echo off
if exist "build_mingw.bat" (
  cd ..
)

set PATH=%PATH:C:\Program Files\Git\usr\bin;=%
set PATH=%PATH:C:\Program Files (x86)\Git\usr\bin;=%

CALL cmake -S . -B build -G "MinGW Makefiles" -DENABLE_SHARED=on -DENABLE_JS_WRAPPER=off -DENABLE_CAPI=on -DENABLE_TESTS=off -DCMAKE_BUILD_TYPE=Release
if not %ERRORLEVEL% == 0 (
    exit /b 1
)

CALL cmake --build build --parallel 4 --config Release
if not %ERRORLEVEL% == 0 (
    exit /b 1
)
