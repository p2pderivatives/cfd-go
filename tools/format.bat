setlocal
@echo off
if exist "format.bat" (
  cd ..
)

CALL go fmt . ./types/... ./errors ./utils ./config ./apis/... ./service/... ./tests
