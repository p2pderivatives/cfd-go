#!/bin/sh
cd `git rev-parse --show-toplevel`
swig -go -DCFD_DISABLE_FREESTRING -outdir . -o cfdgo.c -cgo -intgosize 32 swig.i
