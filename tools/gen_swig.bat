if exist "gen_swig.bat" (
  cd ..
)
swig -go -DCFD_DISABLE_FREESTRING -outdir . -o cfdgo.c -cgo -intgosize 32 swig.i
pause
