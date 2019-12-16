if exist "gen_swig.bat" (
  cd ..
)
swig -c++ -go -DCFD_DISABLE_FREESTRING -outdir . -o cfdgo.cxx -cgo -intgosize 32 swig.i
pause
