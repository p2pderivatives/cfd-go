if exist "gen_swig.bat" (
  cd ..
)
swig -go -outdir . -o cfdgo.c -cgo -intgosize 32 swig.i
pause
