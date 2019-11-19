#!/bin/sh
cd `git rev-parse --show-toplevel`
swig -go -outdir . -o cfdgo.c -cgo -intgosize 32 swig.i
