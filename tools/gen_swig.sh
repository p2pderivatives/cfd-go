#!/bin/sh
cd `git rev-parse --show-toplevel`
swig -c++ -go -DCFD_DISABLE_FREESTRING -outdir . -o cfdgo.cxx -cgo -intgosize 32 swig.i
