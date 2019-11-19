if exist "gen_swig.bat" (
  cd ..
)
swig -go -outdir . -o cfdgo.c -cgo -intgosize 32 src/swig.i
pause
