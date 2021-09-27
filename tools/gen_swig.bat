if exist "gen_swig.bat" (
  cd ..
)

swig -c++ -go -DCFD_DISABLE_FREESTRING -outdir . -o cfdgo.cxx -cgo -intgosize 32 swig.i

powershell -NoProfile -ExecutionPolicy Unrestricted .\tools\convert_crlf.ps1

go fmt cfdgo.go

pause
